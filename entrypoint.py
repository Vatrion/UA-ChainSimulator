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
PORT = 5000         # Port to listen on
SERVER_NAME = "EntrypointTestServer"
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
        'technique': 'Index page for entry points server',
        'default_response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'text/html'}, 'body': b'<html><body><h1>Entry Point Server</h1><p>Test server for malicious redirect chain detection.</p></body></html>'}
    },
    
    # --- Entry Points Based on test_config.txt and payloads.txt ---
    '/entry1': {
        'technique': 'Entry, simple redirect to S2 with suspicious param',
        'default_response': {
            'redirect_to': 'http://192.168.2.69:5001/redirect1?param=%2e%2e%2f'
        }
    },
    '/entry2': {
        'technique': 'Entry, UA-based redirect to S2 with hex IP',
        'ua_rules': [
            {
                'match': {'os': 'Android', 'browser': 'Chrome'},
                'response': {
                    'redirect_to': 'http://0xC0A80245:5001/redirect2'
                }
            },
            {
                'match': {'os': 'iOS', 'browser': 'Safari'},
                'response': {
                    'redirect_to': 'http://192.168.2.69:5001/redirect2?ios_special=1'
                }
            }
        ],
        'default_response': {
            'redirect_to': 'http://192.168.2.69:5001/redirect2'
        }
    },
    '/entry3': {
        'technique': 'Entry, redirect to S2 with embedded credentials',
        'default_response': {
            'redirect_to': 'http://user:pass@192.168.2.69:5001/redirect3'
        }
    },
    '/entry4': {
        'technique': 'Entry, redirect to S2 with punycode domain',
        'default_response': {
            'redirect_to': 'http://xn--spy-vatrion-com:5001/redirect4'
        }
    },
    
    # --- Additional Entry Points based on payloads.txt ---
    '/entry5': {
        'technique': 'Entry, redirect with octal IP',
        'default_response': {
            'redirect_to': 'http://0300.0250.0002.0105:5001/redirect5'
        }
    },
    '/entry6': {
        'technique': 'Entry, redirect with decimal IP',
        'default_response': {
            'redirect_to': 'http://3232236137:5001/redirect6'
        }
    },
    '/entry7': {
        'technique': 'Entry, redirect with IPv6 obfuscated IP',
        'default_response': {
            'redirect_to': 'http://[::C0A8:245]:5001/redirect7'
        }
    },
    '/entry8': {
        'technique': 'Entry, redirect with null byte and special characters',
        'default_response': {
            'redirect_to': 'http://192.168.2.69:5001/redirect8?name=malware%00.exe'
        }
    },
    '/entry9': {
        'technique': 'Entry, redirect with protocol trick (file protocol)',
        'default_response': {
            'redirect_to': 'file:///etc/passwd'
        }
    },
    '/entry10': {
        'technique': 'Entry, redirect with protocol trick (javascript protocol)',
        'default_response': {
            'redirect_to': 'javascript:alert("evil")'
        }
    },
    '/entry11': {
        'technique': 'Entry, redirect with HTML entity bypass',
        'default_response': {
            'redirect_to': 'http://192.168.2.69:5001/redirect9?name=malware&amp;amp;.exe'
        }
    },
    '/entry12': {
        'technique': 'Entry, redirect with Unicode separator bypass',
        'default_response': {
            'redirect_to': 'http://192.168.2.69:5001/redirect10?name=malware%u2028.exe'
        }
    },

    # --- Redirect Examples ---
    '/redirect_simple': {
        'technique': 'Simple 302 redirect',
        'default_response': {'redirect_to': '/normal'} # Default redirect uses 302 Found
    },
    '/redirect_permanent': {
        'technique': 'Permanent 301 redirect',
        'default_response': {'status': HTTPStatus.MOVED_PERMANENTLY, 'redirect_to': '/normal'}
    },
    '/circular_redirect_1': {
        'technique': 'Start of a circular redirect loop',
        'default_response': {'redirect_to': '/circular_redirect_2'}
    },
    '/circular_redirect_2': {
        'technique': 'End of a circular redirect loop',
        'default_response': {'redirect_to': '/circular_redirect_1'}
    },
    '/excessive_redirect_1': {'technique': 'Excessive Redirect Step 1/6', 'default_response': {'redirect_to': '/excessive_redirect_2'}},
    '/excessive_redirect_2': {'technique': 'Excessive Redirect Step 2/6', 'default_response': {'redirect_to': '/excessive_redirect_3'}},
    '/excessive_redirect_3': {'technique': 'Excessive Redirect Step 3/6', 'default_response': {'redirect_to': '/excessive_redirect_4'}},
    '/excessive_redirect_4': {'technique': 'Excessive Redirect Step 4/6', 'default_response': {'redirect_to': '/excessive_redirect_5'}},
    '/excessive_redirect_5': {'technique': 'Excessive Redirect Step 5/6', 'default_response': {'redirect_to': '/excessive_redirect_6'}},
    '/excessive_redirect_6': {'technique': 'Excessive Redirect Step 6/6', 'default_response': {'status': HTTPStatus.OK, 'body': b'Finally reached the end after 6 redirects.'}},

    '/domain_change_redirect': {
        'technique': 'Redirect changing domain',
        # Note: Assumes www.vatrion.com is handled by a different server or resolves elsewhere
        'default_response': {'status': HTTPStatus.FOUND, 'headers': {'Location': f'http://www.vatrion.com:{PORT}/finish'}, 'body': b'Redirecting to another domain...'}
    },
    '/finish': { # Landing page for the domain change
        'technique': 'Final page after domain change',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Landed on www.vatrion.com'}
    },

    # --- User-Agent Specific Behavior ---
    '/ua_specific_content': {
        'technique': 'Serve different content based on User-Agent OS',
        'default_response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'text/html'}, 'body': b'<html><body><h1>Default View</h1><p>Generic content.</p></body></html>'},
        'ua_rules': [
            {'match': {'os': 'Android'}, 'response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'text/html'}, 'body': b'<html><body><h1>Android View</h1><p>Special offer for Android!</p><img src="/android_image.png"></body></html>'}},
            {'match': {'os': 'iOS'}, 'response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'text/html'}, 'body': b'<html><body><h1>iOS View</h1><p>Download from the App Store!</p><a href="#">App Store Link</a></body></html>'}},
            {'match': {'os': 'Windows'}, 'response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'text/html'}, 'body': b'<html><body><h1>Windows View</h1><p>Install our Desktop App!</p><button>Download .exe</button></body></html>'}},
            # Add more rules as needed, e.g., for Linux, macOS, specific browsers
        ]
    },
    '/ua_specific_redirect': {
        'technique': 'Redirect to different paths based on User-Agent OS',
        'default_response': {'redirect_to': '/normal'}, # Default target
        'ua_rules': [
            {'match': {'os': 'Android'}, 'response': {'redirect_to': '/android_landing'}},
            {'match': {'os': 'iOS'}, 'response': {'redirect_to': '/ios_landing'}},
             # Example: Redirect specific old browser
            {'match': {'browser': 'IE'}, 'response': {'redirect_to': '/unsupported_browser'}},
        ]
    },
    '/android_landing': {'technique': 'Landing page for Android UAs', 'default_response': {'status': HTTPStatus.OK, 'body': b'Welcome Android User!'}},
    '/ios_landing': {'technique': 'Landing page for iOS UAs', 'default_response': {'status': HTTPStatus.OK, 'body': b'Welcome iOS User!'}},
    '/unsupported_browser': {'technique': 'Page for unsupported browsers', 'default_response': {'status': HTTPStatus.OK, 'body': b'Please upgrade your browser.'}},


    # --- Exploit/Technique Simulations ---
    # Category 1: Domain-Based
    '/non_existing_domain_target': {
        'technique': 'Redirect to a non-resolvable domain',
        'default_response': {'status': HTTPStatus.FOUND, 'headers': {'Location': 'http://domain-that-doesnt-exist-vatrion.xyz/final'}, 'body': b'Redirecting...'}
    },
     '/blocked_tld_target': {
        'technique': 'Redirect to a blocked TLD (.zip)',
        'default_response': {'redirect_to': '/final_blocked.zip'} # Path ends with .zip, server serves it
    },
     '/final_blocked.zip': { # Actual path simulating blocked TLD access
        'technique': 'Target page for blocked TLD',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed resource on .zip TLD'}
    },
    '/homograph_cyrillic': {
        'technique': 'Path containing Cyrillic characters (Homograph)',
        # The path itself is the indicator. Scanner needs to check path components.
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed Cyrillic path.'}
    },

    # Category 2: URL Structure
    '/protocol_javascript_redirect': {
        'technique': 'Redirect using javascript: protocol',
        'default_response': {'status': HTTPStatus.FOUND, 'headers': {'Location': 'javascript:alert("Evil Elias was here!")'}, 'body': b'Redirecting...'}
    },
    '/auth_in_url_resource': {
        'technique': 'Resource requiring auth info in URL (user:pass@...)',
        # Server doesn't enforce auth, relies on scanner detecting it in the request URL
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed resource behind simulated auth.'}
    },
    '/base64_payload_required': {
        'technique': 'Requires Base64 encoded query parameter',
        # Logic handled within do_GET - check query param 'data'
        'default_response': {'status': HTTPStatus.BAD_REQUEST, 'body': b'Missing or invalid Base64 parameter "data".'} # Default if logic fails
    },
    '/multi_encoded_path_target': {
        'technique': 'Target for multi-encoded path request',
        # Example access URL: /multi_encoded_path_target%252Fsecret
        'default_response': {'status': HTTPStatus.OK, 'body': b'Reached multi-encoded path target.'}
    },

    # Category 3: IP Obfuscation
    '/ip_obfuscation_target': {
        'technique': 'Generic target for IP obfuscation tests',
        # Scanner checks the Host header or initial URL used to reach this.
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via potentially obfuscated IP.'}
    },
    # Add specific paths if needed, e.g., '/target_for_hex_ip', but generally one target is fine.

    # Category 4: Path Traversal & URL Tricks
    '/path_traversal_target': {
        'technique': 'Target for path traversal attempt in query',
        # Example access URL: /path_traversal_target?file=../../secret
        'default_response': {'status': HTTPStatus.OK, 'body': b'Simulated file access endpoint.'} # Check query params in handler if needed
    },
     '/url_trick_slash_target': {
        'technique': 'Target for URL trick with double/triple slashes',
         # Access via ///url_trick_slash_target
        'default_response': {'status': HTTPStatus.OK, 'body': b'Reached target despite extra slashes.'}
    },
     '/url_trick_at_target': {
        'technique': 'Target for URL trick with @ symbol',
         # Access via /login@well.vatrion.com:8080/url_trick_at_target
        'default_response': {'status': HTTPStatus.OK, 'body': b'Reached target despite @ symbol.'}
    },

    # Category 5: Unicode & Encoding
     '/unicode_bypass_target': {
        'technique': 'Target for Unicode normalization bypass',
         # Access via /unicode_bypass_target%u200B or similar
        'default_response': {'status': HTTPStatus.OK, 'body': b'Reached target despite Unicode tricks.'}
    },
     '/double_encoding_target': {
        'technique': 'Target for double encoding bypass',
         # Access via /double_encoding_target%252Fsecret
        'default_response': {'status': HTTPStatus.OK, 'body': b'Reached target despite double encoding.'}
    },

    # Category 6: Domain Obfuscation
     '/punycode_target': {
         'technique': 'Target for Punycode domain request (e.g., xn--)',
         # Scanner needs to detect the Punycode in the Host header/initial URL
         'default_response': {'status': HTTPStatus.OK, 'body': b'Reached Punycode target.'}
     },

    # Category 8: Character Manipulation
     '/character_manipulation_target': {
         'technique': 'Target for non-Latin characters in path/query',
          # Access via /search?q=你好 or similar
         'default_response': {'status': HTTPStatus.OK, 'body': b'Reached target with manipulated characters.'}
     },

    # Category 9: Payload Indicators
     '/download.exe': {
        'technique': 'Path with suspicious .exe extension',
        'default_response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'application/octet-stream'}, 'body': b'Simulated EXE file content.'}
    },
     '/user_login': {
        'technique': 'Path matching ATO patterns (login)',
        'default_response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'text/html'}, 'body': b'<html><body>Login Page Simulation</body></html>'}
    },
     '/null_byte_target': {
        'technique': 'Target for null byte injection attempt',
         # Access via /file?name=image.jpg%00.txt
        'default_response': {'status': HTTPStatus.OK, 'body': b'Reached null byte target.'}
    },
     '/url_in_query_target': {
        'technique': 'Target for URL embedded in query parameter',
         # Access via /load?redir=http://well.vatrion.com:8080/malicious
        'default_response': {'status': HTTPStatus.OK, 'body': b'Reached target with URL in query.'}
    },

    # Category 11: Protocol & Structure Violations
    '/double_slash_target': {
        'technique': 'Target accessed via double slash after domain',
        # Access like http://well.vatrion.com:8080//double_slash_target
        'default_response': {'status': HTTPStatus.OK, 'body': b'Reached target despite double slash.'}
    },

    '/hex_ip_target': {
        'technique': 'Access via hexadecimal IP (0xC0A80245 for 192.168.2.69)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via hex IP.'}
    },
    '/octal_ip_target': {
        'technique': 'Access via octal IP (0300.0250.0002.0105 for 192.168.2.69)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via octal IP.'}
    },
    '/decimal_ip_target': {
        'technique': 'Access via decimal IP (3232236137 for 192.168.2.69)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via decimal IP.'}
    },
    '/binary_ip_target': {
        'technique': 'Access via binary IP (11000000.10101000.00000010.01000101 for 192.168.2.69)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via binary IP.'}
    },
    '/ipv6_obfuscation_target': {
        'technique': 'Access via IPv6 obfuscated address ([::C0A8:245] for 192.168.2.69)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via IPv6 obfuscated IP.'}
    },
    '/localhost_variant_target': {
        'technique': 'Access via localhost variant (127.0.0.1, [::1], loopback)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via localhost variant.'}
    },
    '/url_encoded_path_target': {
        'technique': 'Access via URL-encoded path (%2e%2e%2f for ../)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via URL-encoded path.'}
    },
    '/unicode_zero_width_target': {
        'technique': 'Access via zero-width unicode character (\u200b)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via zero-width unicode.'}
    },
    '/html_entity_chain_target': {
        'technique': 'Access via HTML entity chaining (&amp;amp;)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via HTML entity chaining.'}
    },
    '/regex_bypass_newline_target': {
        'technique': 'Access via regex bypass using newline',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via regex bypass (newline).'}
    },
    '/regex_bypass_unicode_sep_target': {
        'technique': 'Access via regex bypass using unicode separator (\u2028)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via regex bypass (unicode separator).'}
    },
    '/punycode_xn_target': {
        'technique': 'Access via Punycode domain (xn--spy-vatrion-com)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via Punycode domain.'}
    },
    '/file_extension_rar': {
        'technique': 'Suspicious .rar file extension',
        'default_response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'application/octet-stream'}, 'body': b'Simulated RAR file content.'}
    },
    '/file_extension_php': {
        'technique': 'Suspicious .php file extension',
        'default_response': {'status': HTTPStatus.OK, 'headers': {'Content-Type': 'text/plain'}, 'body': b'<?php echo \'Evil\'; ?>'}
    },
    '/triple_slash_target': {
        'technique': 'Access via triple slash (///triple_slash_target)',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via triple slash.'}
    },
    '/protocol_ftp_target': {
        'technique': 'Access via ftp: protocol',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via ftp protocol.'}
    },
    '/protocol_file_target': {
        'technique': 'Access via file: protocol',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via file protocol.'}
    },
    '/protocol_data_target': {
        'technique': 'Access via data: protocol',
        'default_response': {'status': HTTPStatus.OK, 'body': b'Accessed via data protocol.'}
    },

    # --- Customizable Scanner Test Endpoints ---
    '/endpoint1': {
        'technique': 'Redirect to hex IP and .exe',
        'default_response': {
            'redirect_to': 'http://0xC0A80245:5000/malware.exe'
        }
    },
    '/endpoint2': {
        'technique': 'Serve .php file',
        'file_mode': True,
        'file_path': 'malicious.php',  # <--- Place this file in the same directory
        'default_response': {
            'headers': {'Content-Type': 'text/plain'},
            'status': HTTPStatus.OK
        }
    },
    '/endpoint3': {
        'technique': 'HTML with suspicious link',
        'html_body': b'<html><body><a href="/malware.exe?param=%2e%2e%2f">Download</a></body></html>',
        'default_response': {
            'body': b'Plain fallback',
            'headers': {'Content-Type': 'text/plain'},
            'status': HTTPStatus.OK
        }
    },
    '/endpoint4': {
        'technique': 'UA-based redirect',
        'ua_rules': [
            {
                'match': {'os': 'Android', 'browser': 'Chrome'},
                'response': {
                    'redirect_to': 'ftp://well.vatrion.com/malware.exe'
                }
            }
        ],
        'default_response': {
            'body': b'Default for all other UAs',
            'headers': {'Content-Type': 'text/plain'},
            'status': HTTPStatus.OK
        }
    },
    '/endpoint5': {
        'technique': 'Multi-trick: redirect with embedded credentials and encoded path',
        'default_response': {
            'redirect_to': 'http://user:pass@0xC0A80245:5000/%2e%2e%2fmalware.exe?param=%00&amp;amp;'
        }
    },

    # --- Comprehensive Test Config Coverage ---
    # Redirect/Evasion Points from test_config.txt
    '/redirect1': {
        'technique': 'Redirect to S3 with double encoding and null byte',
        'default_response': {
            'redirect_to': 'http://192.168.2.70:5000/payload1?file=%252e%252e%252fsecret.txt%00'
        }
    },
    '/redirect2': {
        'technique': 'UA-based: Android Chrome gets FTP, others get S4 with octal IP',
        'ua_rules': [
            {'match': {'os': 'Android', 'browser': 'Chrome'}, 'response': {'redirect_to': 'ftp://well.vatrion.com/payload3'}}
        ],
        'default_response': {
            'redirect_to': 'http://0300.0250.0002.0105:5000/payload2'
        }
    },
    '/redirect3': {
        'technique': 'Redirect to S4 with suspicious file extension and unicode',
        'default_response': {
            'redirect_to': 'http://well.vatrion.com:5000/payload4/%E2%80%8Bmalware.exe'
        }
    },
    '/redirect4': {
        'technique': 'Redirect to S3 with embedded credentials and path traversal',
        'default_response': {
            'redirect_to': 'http://admin:admin@192.168.2.70:5000/payload2?name=../../etc/passwd'
        }
    },
    # Payload Endpoints from test_config.txt
    '/payload1': {
        'technique': 'Serve .php file with encoded path',
        'file_mode': True,
        'file_path': 'malicious.php',
        'default_response': {
            'headers': {'Content-Type': 'text/plain'},
            'status': 200
        }
    },
    '/payload2': {
        'technique': 'Serve .exe file, suspicious param, and HTML with link to S4',
        'file_mode': True,
        'file_path': 'malware.exe',
        'html_body': b'<html><body>Next: <a href="http://well.vatrion.com:5000/payload3?redir=ftp://malicious.zip/malware.exe">payload3</a></body></html>',
        'default_response': {
            'headers': {'Content-Type': 'application/octet-stream'},
            'status': 200
        }
    },
    # S4 Payloads
    '/payload3': {
        'technique': 'FTP payload, suspicious .rar extension',
        'default_response': {
            'body': b'Simulated RAR file content.',
            'headers': {'Content-Type': 'application/octet-stream'},
            'status': 200
        }
    },
    '/payload4': {
        'technique': 'HTML with cyrillic and encoded param, serves .jsp file',
        'html_body': b'<html><body>Download: <a href="/file.jsp?param=%D0%90">file.jsp</a></body></html>',
        'file_mode': True,
        'file_path': 'file.jsp',
        'default_response': {
            'headers': {'Content-Type': 'text/plain'},
            'status': 200
        }
    },
    # Add more payload definitions here based on the list...

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
                    'redirect_to': 'https://well.vatrion.com:5000/index.html'
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
                    redirect_url = resp['redirect_to'] # Get the redirect URL
                    # Handle redirect for UA match
                    self.send_response(HTTPStatus.FOUND)
                    self.send_header('Location', redirect_url) # Use the redirect_url
                    self.end_headers()
                    # Log the specific redirect being sent for this UA match
                    logging.info(f"[{ua_info['os']}/{ua_info['browser']}] UA rule matched for {path}. Redirecting to: {redirect_url}")
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

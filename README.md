# React2Shell Security Tool

<div align="center">
<img width="500" height="572" alt="logo" src="https://github.com/user-attachments/assets/883e27f2-d59f-41ed-9126-4073c8b45dc4" />
</div>

## Overview

**CVE-2025-55182 & CVE-2025-66478**

A comprehensive security testing toolkit for identifying and exploiting Next.js React Server Components (RSC) vulnerabilities. This tool provides automated scanning, vulnerability detection, and exploitation capabilities for security researchers and penetration testers.

## Features

- **Automated Vulnerability Scanner** - Detect RSC vulnerabilities in Next.js applications
- **Shodan Integration** - Mass scanning using Shodan API for large-scale discovery
- **CORS Proxy Server** - Built-in proxy for bypassing CORS restrictions
- **Interactive CLI** - User-friendly menu-driven interface
- **Detailed Reporting** - JSON and text-based vulnerability reports
- **Multi-threaded Scanning** - Fast concurrent vulnerability detection

## Requirements

- Python 3.8+
- Valid Shodan API key (for mass scanning)

## Installation

```bash
# Clone the repository
git clone https://github.com/enesbuyuk/react2shell-security-tool.git
cd react2shell-security-tool

# Install dependencies
pip install -r requirements.txt

# Configure your Shodan API key
cp .env.example .env
# Edit .env and add your SHODAN_API_KEY
```

## Usage

### Main Interface

Start the interactive menu:

```bash
python3 main.py
```

**Menu Options:**
1. **Proxy Server** - Start CORS-enabled proxy (runs in background)
2. **Next.js Scanner** - Scan single target for vulnerabilities
3. **Shodan Scanner** - Mass scan using Shodan API
4. **About Tools** - Information about each tool

### Individual Tools

**Scan a single target:**
```bash
python3 exploit.py https://example.com
```

**Batch scan from file:**
```bash
python3 exploit.py urls.txt
```

**Run Shodan scanner:**
```bash
python3 tools/shodan_scanner.py
```

**Start CORS proxy:**
```bash
python3 cors_proxy.py
```

## Configuration

### Environment Variables (.env)
```bash
SHODAN_API_KEY=your_shodan_api_key_here
```

### Shodan Queries (shodan_queries.txt)
Customize Shodan search queries by editing `shodan_queries.txt`:
```
http.html:"__NEXT_DATA__"
http.html:"_next/static"
# Add your custom queries here
```

## Project Structure

```
.
├── main.py                 # Main interactive menu
├── tools/
│   ├── exploit.py          # Next.js vulnerability scanner
│   ├── cors_proxy.py       # CORS proxy server
│   └── shodan_scanner.py   # Shodan mass scanner
├── results/                # Scan results directory
├── shodan_queries.txt      # Shodan search queries
├── requirements.txt        # Python dependencies
├── .env                    # Environment configuration
└── README.md              # This file
```

## Legal Disclaimer

This tool is for **educational and authorized security testing purposes only**. 

- Only use on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal
- The authors are not responsible for misuse or damage caused by this tool
- Always comply with applicable laws and regulations

## Vulnerability Details

### CVE-2025-55182 & CVE-2025-66478

These vulnerabilities affect Next.js applications using React Server Components (RSC):

- **Impact**: Remote Code Execution (RCE)
- **Affected**: Next.js applications with RSC enabled
- **CVSS Score**: Critical
- **Vector**: Prototype pollution leading to arbitrary code execution

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

This project is for educational purposes only. Use at your own risk.

## Credits

**Emre Davut**
- GitHub: [@emredavut](https://github.com/emredavut) - [CVE-2025-55182](https://github.com/emredavut/CVE-2025-55182)

**assetnote**
- Github: [@assetnote](https://github.com/assetnote) - [react2shell-scanner](https://github.com/assetnote/react2shell-scanner)

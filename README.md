# N0aziXss Origin Recon v3.1 🍓

## 🌟 Introduction
**N0aziXss Origin Recon** Advanced reconnaissance tool for subdomain enumeration, IP analysis, and origin server detection with multi-layer security checks.

## Features ✨
- Subdomain extraction via Certificate Transparency (CRT.sh)
- DNS resolution with SSRF protection
- IP geolocation and ASN analysis
- Common port scanning (80, 443, 22, etc.)
- Critical origin IP detection (non-CDN)
- SSL/TLS certificate analysis (optional)
- Error logging and reporting system
- JSON output support

## Requirements ⚙️
- Python 3.8+
- Required libraries: `pip install -r requirements.txt`

## Installation 📦
```bash
git clone https://github.com/NazaninNazari/Origin_Recon.git
cd Origin_Recon-tools

# install dependencies
pip install -r requirements.txt

#Usage
python origin_recon.py -d example.com [--ssl] [--output results.json]

## Options
-d & --domain --> Target domain (required)
--ssl --> Enable SSL/TLS scanning (optional)
--output --> Save results to JSON file (optional)

# Sample Output
                           🔥 Scan Results for example.com 🔥                                     
┌─────────────────────────┬──────────────────────┬───────────────────────┬─────────────────┐
│ Subdomain               │ IP Addresses         │ ASN                   │ Open Ports      │
├─────────────────────────┼──────────────────────┼───────────────────────┼─────────────────┤
│ mail.example.com        │ 192.0.2.1            │ AS15169 (Google LLC)  │ 80, 443         │
│                         │                      │ [dim]US/California[/] │                 │
├─────────────────────────┼──────────────────────┼───────────────────────┼─────────────────┤
│ api.example.com         │ 203.0.113.5          │ AS13335 (Cloudflare)  │ 443, 8080       │
│                         │                      │ [dim]DE/Frankfurt[/]  │                 │
└─────────────────────────┴──────────────────────┴───────────────────────┴─────────────────┘

                      🔥 Critical Origin IPs 🔥                              
┌─────────────────┬───────────────────────────────┬─────────────────────────┐
│ IP              │ Detection Reasons             │ Risk Level              │
├─────────────────┼───────────────────────────────┼─────────────────────────┤
│ 198.51.100.22   │ High TTL (3600s)              │ [bold]High Risk[/]      │
│                 │ Server: Apache/2.4.29         │                         │
└─────────────────┴───────────────────────────────┴─────────────────────────┘
 
                       ⚠ Error Summary ⚠
┌──────────┬──────────────────────┬─────────────────────────────┐
│ Time     │ Type                 │ Message                     │
├──────────┼──────────────────────┼─────────────────────────────┤
│ 12:34:56 │ CRT.sh Connection    │ Server took too long...     │
└──────────┴──────────────────────┴─────────────────────────────┘

✓ Scan completed in 0:01:23
Total Subdomains: 15
Unique IPs Found: 9
Critical Findings: 1
Errors Occurred: 1
✓ Results saved to results.json
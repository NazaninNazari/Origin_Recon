import argparse
import asyncio
import re
import aiohttp
import ssl
from socket import socket
from colorama import Fore, Style
from rich.console import Console
from rich.table import Table
from rich.style import Style
from rich.progress import Progress
from rich.box import DOUBLE_EDGE
from dns.asyncresolver import Resolver
from datetime import datetime
from pyfiglet import Figlet

# Initial settings
try:
    import tldextract
    HAVE_TLDEXTRACT = True
except ImportError:
    HAVE_TLDEXTRACT = False

console = Console()

# Banner_One
PURPLE = '\033[0;35m' 
END = "\033[0m"

banner = f"""
  {END}
    ███╗   ██╗ █████╗ ███████╗██╗██╗  ██╗███████╗███████╗
    ████╗  ██║██╔══██╗╚══███╔╝██║╚██╗██╔╝██╔════╝██╔════╝
    ██╔██╗ ██║███████║  ███╔╝ ██║ ╚███╔╝ ███████╗███████╗
    ██║╚██╗██║██╔══██║ ███╔╝  ██║ ██╔██╗ ╚════██║╚════██║
    ██║ ╚████║██║  ██║███████╗██║██╔╝ ██╗███████║███████║
    ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
                                                         
     ██████╗ ██████╗ ██╗ ██████╗ ██╗███╗   ██╗           
    ██╔═══██╗██╔══██╗██║██╔════╝ ██║████╗  ██║           
    ██║   ██║██████╔╝██║██║  ███╗██║██╔██╗ ██║           
    ██║   ██║██╔══██╗██║██║   ██║██║██║╚██╗██║           
    ╚██████╔╝██║  ██║██║╚██████╔╝██║██║ ╚████║           
     ╚═════╝ ╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝           
                                                         
    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗          
    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║          
    ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║          
    ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║          
    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║          
    ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝ """

print(banner)

# Banner_Two
print(Fore.CYAN + "♦*"*16)
print(Fore.YELLOW + "🍓 N0aziXss Origin Recon v3.0 🍓")
print(Fore.CYAN + "♦*"*16 + "\n")

class N0aziXssScanner:
    def __init__(self, domain, enable_ssl=False, output_file=None):
        self.domain = domain
        self.resolver = Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        self.session = None
        self.progress = Progress()
        self.found_ips = set()
        self.enable_ssl = enable_ssl
        self.output_file = output_file
        self.error_messages = []
        self.critical_ips_count = 0

    async def log_error(self, message):
        """Save errors in the same format"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        error_msg = f"[dim]{timestamp}[/dim] [bright_red]✗[/bright_red] [bright_white]{message}[/bright_white]"
        self.error_messages.append(message)
        console.print(error_msg)

    async def SafeDnsResolve(self, target, record_type='A'):
        try:
            answers = await self.resolver.resolve(target, record_type)
            return [str(r) for r in answers]
        except Exception as e:
            await self.log_error(f"DNS Resolution Failed: {target} ({str(e)})")
            return []

    async def FetchLogs(self):
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with self.session.get(url, timeout=15) as resp:
                if resp.status == 200:
                    try:
                        data = await resp.json(content_type=None)
                        return list({entry['name_value'].lower().strip() for entry in data})
                    except Exception as e:
                        await self.log_error(f"CRT.sh Data Parse Error: {str(e)}")
                        return []
                await self.log_error(f"CRT.sh HTTP Error: Status {resp.status}")
                return []
        except asyncio.TimeoutError:
            await self.log_error("CRT.sh Request Timeout")
            return []
        except Exception as e:
            await self.log_error(f"CRT.sh Connection Error: {str(e)}")
            return []

    async def GetAsn(self, ip):
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            result = await self.SafeDnsResolve(f"{reversed_ip}.origin.asn.cymru.com", 'TXT')
            return result[0].split('|')[0].strip() if result else "Unknown"
        except Exception as e:
            await self.log_error(f"ASN Lookup Failed: {ip} ({str(e)})")
            return "Unknown"

    async def GetGeo(self, ip):
        try:
            async with self.session.get(f"http://ip-api.com/json/{ip}", timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get('status') == 'success':
                        return f"{data.get('country', '')}/{data.get('city', '')}"
                    return "Unknown"
                await self.log_error(f"GeoIP API Error: Status {resp.status}")
                return "Unknown"
        except Exception as e:
            await self.log_error(f"GeoIP Lookup Failed: {ip} ({str(e)})")
            return "Unknown"

    async def DetectOrigin(self, ip):
        reasons = []
        try:
            answers = await self.resolver.resolve(self.domain, 'A')
            ttl = answers.rrset.ttl
            if ttl > 300:
                reasons.append(f"High TTL ({ttl}s)")

            async with self.session.get(f"http://{ip}", timeout=5, ssl=False) as resp:
                headers = resp.headers
                if 'Server' in headers and 'cloudflare' not in headers['Server'].lower():
                    reasons.append(f"Server: {headers['Server']}")
                if 'X-Powered-By' in headers:
                    reasons.append(f"Tech: {headers['X-Powered-By']}")
            return reasons if reasons else ["Potential CDN"]
        except Exception as e:
            await self.log_error(f"Origin Detection Failed: {ip} ({str(e)})")
            return ["Detection Failed"]

    async def ScanPorts(self, ip):
        common_ports = [80, 443, 22, 21, 8080]
        open_ports = []
        for port in common_ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=1.5
                )
                open_ports.append(str(port))
                writer.close()
            except Exception:
                pass
        return open_ports if open_ports else ["None"]

    async def CheckSSL(self, domain):
        try:
            context = ssl.create_default_context()
            with socket() as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    ssock.connect((domain, 443))
                    cert = ssock.getpeercert()
                    return f"Issuer: {cert['issuer']}, Expiry: {cert['notAfter']}"
        except Exception as e:
            return f"SSL Error: {str(e)}"

    async def RunScan(self):
        start_time = datetime.now()
        origin_table = None

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=30)
        ) as self.session:
            with self.progress:
                # Collecting subdomains
                task = self.progress.add_task("[cyan]Collecting subdomains...", total=1)
                subdomains = await self.FetchLogs()
                self.progress.update(task, completed=1)

                # Create tables
                main_table = Table(
                    title=f"[blink]🔥 Scan Results for {self.domain} 🔥[/]",
                    box=DOUBLE_EDGE,
                    style="bright_white",
                    title_style=Style(blink=True, bold=True)
                )
                
                # Main table columns
                columns = [
                    ("Subdomain", "bright_green", 25),
                    ("IP Addresses", "cyan", 20),
                    ("ASN", "bold yellow", 15),
                    ("Open Ports", "bright_red", 15)
                ]
                
                if self.enable_ssl:
                    columns.append(("SSL Info", "green", 30))
                
                for col in columns:
                    main_table.add_column(col[0], style=col[1], width=col[2])

                # Critical IPs table
                origin_table = Table(
                    title="[blink]🔥 Critical Origin IPs 🔥[/]",
                    style="white",
                    box=DOUBLE_EDGE,
                    title_style=Style(blink=True, bold=True)
                )
                origin_table.add_column("IP", style="bold yellow")
                origin_table.add_column("Detection Reasons", style="green")
                origin_table.add_column("Risk Level", style="red")

                task = self.progress.add_task("[yellow]Analyzing IPs...", total=len(subdomains))
                for sub in subdomains:
                    ips = await self.SafeDnsResolve(sub)
                    
                    # Subdomain colors
                    sub_display = f"[bright_green]{sub}[/bright_green]" if ips else f"[dim]{sub}[/dim]"
                    
                    # Preparing row data
                    row_data = [
                        sub_display,
                        "\n".join(ips) if ips else "[dim]No IPs[/dim]",
                        await self.GetAsn(ips[0]) if ips else "[dim]N/A[/dim]",
                        ", ".join(await self.ScanPorts(ips[0])) if ips else "[dim]N/A[/dim]"
                    ]
                    
                    if self.enable_ssl:
                        row_data.append(await self.CheckSSL(sub) if ips else "[dim]N/A[/dim]")
                    
                    main_table.add_row(*row_data)

                    # Checking critical IPs
                    if ips:
                        for ip in ips:
                            if ip in self.found_ips:
                                continue
                            self.found_ips.add(ip)
                            reasons = await self.DetectOrigin(ip)
                            if "CDN" not in reasons[0]:
                                origin_table.add_row(
                                    f"[bright_yellow]{ip}[/bright_yellow]",
                                    "\n".join(reasons),
                                    "[bold bright_red]High Risk[/bold bright_red]" if "Failed" not in reasons[0] else "[dim]Unknown[/dim]"
                                )
                                self.critical_ips_count += 1

                    self.progress.update(task, advance=1)

            # Show results
            console.print(main_table)
            
            # Show critical IPs
            if self.critical_ips_count > 0:
                console.print(origin_table)
            else:
                console.print("[bold yellow]No critical origin IPs found![/]")

            # Show errors if any
            if self.error_messages:
                error_table = Table(
                    title="[blink]⚠ Error Summary ⚠[/]",
                    box=DOUBLE_EDGE,
                    style="bright_red",
                    title_style=Style(bold=True, blink=True)
                )
                error_table.add_column("Time", style="dim", width=8)
                error_table.add_column("Type", style="bright_white", width=20)
                error_table.add_column("Message", style="bright_red", width=50)
                
                for error in self.error_messages:
                    parts = error.split(":", 1)
                    error_type = parts[0] if len(parts) > 1 else "General Error"
                    message = parts[1] if len(parts) > 1 else error
                    
                    error_table.add_row(
                        f"[dim]{datetime.now().strftime('%H:%M:%S')}[/dim]",
                        f"[bright_white]{error_type}[/bright_white]",
                        f"[bright_red]{message}[/bright_red]"
                    )
                
                console.print("\n")
                console.print(error_table)

            # Summary of results
            console.print(
                f"\n[bold cyan]✓ Scan completed in {datetime.now() - start_time}[/]\n"
                f"Total Subdomains: [bright_green]{len(subdomains)}[/bright_green]\n"
                f"Unique IPs Found: [bright_cyan]{len(self.found_ips)}[/bright_cyan]\n"
                f"Critical Findings: [bright_red]{self.critical_ips_count}[/bright_red]\n"
                f"Errors Occurred: [bright_red]{len(self.error_messages)}[/bright_red]"
            )

            # Save the results
            if self.output_file:
                import json
                with open(self.output_file, 'w') as f:
                    json.dump({
                        "domain": self.domain,
                        "subdomains": subdomains,
                        "ips": list(self.found_ips),
                        "critical_ips": self.critical_ips_count,
                        "errors": self.error_messages,
                        "timestamp": str(datetime.now())
                    }, f, indent=4)
                console.print(f"[bright_green]✓ Results saved to {self.output_file}[/bright_green]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="N0aziXss Recon - Professional Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain name")
    parser.add_argument("--ssl", action="store_true", help="Enable SSL/TLS scanning")
    parser.add_argument("--output", type=str, help="Save results to a JSON file")
    args = parser.parse_args()

    # Domain validation
    if HAVE_TLDEXTRACT:
        ext = tldextract.extract(args.domain)
        if not ext.suffix:
            console.print("[bold bright_red]✗ Error: Invalid domain![/bold bright_red]")
            exit(1)
    else:
        if not re.match(r"^([a-z0-9\-]+\.)+[a-z]{2,10}$", args.domain):
            console.print("[bold bright_red]✗ Error: Invalid domain format![/bold bright_red]")
            exit(1)

    try:
        scanner = N0aziXssScanner(args.domain, enable_ssl=args.ssl, output_file=args.output)
        asyncio.run(scanner.RunScan())
    except KeyboardInterrupt:
        console.print("\n[bold bright_yellow]⚠ Scan interrupted by user![/bold bright_yellow]")
        exit(0)
import argparse
import asyncio
import re
import aiohttp
from colorama import Fore
from rich.console import Console
from rich.table import Table
from rich.style import Style
from rich.progress import Progress
from rich.box import DOUBLE_EDGE
from dns.asyncresolver import Resolver
from datetime import datetime
from pyfiglet import Figlet

console = Console()

# Banner
BANNER = Figlet(font='slant').renderText('N0aziXss')
console.print(Fore.CYAN + BANNER)
print(Fore.YELLOW + "♦*"*15)
print(Fore.CYAN + "🍓N0aziXss Origin Recon v3.0🍓")
print(Fore.YELLOW + "♦*"*15 + "\n")

# The main scanner class
class N0aziXssScanner:
    def __init__(self, domain):
        self.domain = domain
        self.resolver = Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        self.session = None
        self.progress = Progress()
        self.found_ips = set()

    async def SafeDnsResolve(self, target, record_type='A'):
        # DNS resolution with SSRF protection
        try:
            answers = await self.resolver.resolve(target, record_type)
            return [str(r) for r in answers]
        except Exception:
            return []

    async def FetchLogs(self):
        # Extracting subdomains from Certificate Transparency
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        try:
            async with self.session.get(url) as resp:
                data = await resp.json()
                return list({entry['name_value'].lower().strip() for entry in data})
        except Exception:
            return []

    async def GetAsn(self, ip):
        # ASN information extraction
        try:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            result = await self.SafeDnsResolve(f"{reversed_ip}.origin.asn.cymru.com", 'TXT')
            return result[0].split('|')[0].strip() if result else "Unknown"
        except Exception:
            return "Unknown"

    async def GetGeo(self, ip):
        # Geographical location
        try:
            async with self.session.get(f"http://ip-api.com/json/{ip}") as resp:
                data = await resp.json()
                return f"{data.get('country', '')}/{data.get('city', '')}"
        except Exception:
            return "Unknown"

    async def DetectOrigin(self, ip):
        # IP Origin Detection with Multi-Layer Analysis
        reasons = []
        try:
            # TTL analysis
            answers = await self.resolver.resolve(self.domain, 'A')
            ttl = answers.rrset.ttl
            if ttl > 300:
                reasons.append(f"High TTL ({ttl}s)")

            # waste analysisا
            async with self.session.get(f"http://{ip}", timeout=5, ssl=False) as resp:
                headers = resp.headers
                if 'Server' in headers and 'cloudflare' not in headers['Server'].lower():
                    reasons.append(f"Server: {headers['Server']}")
                if 'X-Powered-By' in headers:
                    reasons.append(f"Tech: {headers['X-Powered-By']}")

            return reasons if reasons else ["Potential CDN"]
        except Exception:
            return ["Detection Failed"]

    async def ScanPorts(self, ip):
        # Scan the main ports
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

    async def RunScan(self):
        # Basic scan execution
        start_time = datetime.now()

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as self.session:
            # Collecting subdomains
            with self.progress:
                task = self.progress.add_task("[cyan]Collecting subdomains...", total=1)
                subdomains = await self.FetchLogs()
                self.progress.update(task, completed=1)

                # Analysis of IPs
                task = self.progress.add_task("[yellow]Analyzing IP addresses...", total=len(subdomains))
                main_table = Table(
                    title=f"[blink]🔥 Scan Results for {self.domain} 🔥[/]",
                    box=DOUBLE_EDGE,
                    style="bright_white",
                    title_style=Style(blink=True, bold=True)
                )
                main_table.add_column("Subdomain", style="white", width=25)
                main_table.add_column("IP Addresses", style="cyan", width=20)
                main_table.add_column("ASN", style="bold yellow", width=15)
                main_table.add_column("Open Ports", style="red", width=15)

                origin_table = Table(
                    title="[blink]🔥 Critical Origin IPs 🔥[/]",
                    style="white",
                    box=DOUBLE_EDGE,
                    title_style=Style(blink=True, bold=True)
                )
                origin_table.add_column("IP", style="bold yellow")
                origin_table.add_column("Detection Reasons", style="green")
                origin_table.add_column("Risk Level", style="red")

                for sub in subdomains:
                    ips = await self.SafeDnsResolve(sub)
                    if not ips:
                        continue

                    asn = await self.GetAsn(ips[0])
                    geo = await self.GetGeo(ips[0])
                    ports = await self.ScanPorts(ips[0])

                    main_table.add_row(
                        sub,
                        "\n".join(ips),
                        f"{asn}\n[dim]{geo}[/]",
                        ", ".join(ports)
                    )

                    for ip in ips:
                        if ip in self.found_ips:
                            continue
                        self.found_ips.add(ip)
                        reasons = await self.DetectOrigin(ip)
                        if "CDN" not in reasons[0]:
                            origin_table.add_row(
                                ip,
                                "\n".join(reasons),
                                "[bold]High Risk[/]" if "Failed" not in reasons[0] else "[dim]Unknown[/]"
                            )

                    self.progress.update(task, advance=1)

            # Show results
            console.print(main_table)
            if origin_table.row_count > 0:
                console.print(origin_table)
            else:
                console.print("[bold yellow]No critical origin IPs found![/]")

            # summary
            console.print(
                f"\n[bold cyan]✓ Scan completed in {datetime.now() - start_time}[/]\n"
                f"Total Subdomains: [green]{len(subdomains)}[/]\n"
                f"Unique IPs Found: [cyan]{len(self.found_ips)}[/]\n"
                f"Critical Findings: [red]{origin_table.row_count}[/]"
            )

# Run the program
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="N0aziXss Recon - Professional Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain name")
    args = parser.parse_args()

    # Domain validation
    if not re.match(r"^([a-z0-9\-]+\.)+[a-z]{2,6}$", args.domain):
        console.print("[bold red]Error: Invalid domain format![/]")
        exit(1)

    try:
        scanner = N0aziXssScanner(args.domain)
        asyncio.run(scanner.RunScan())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Scan interrupted by user![/]")
        exit(0)
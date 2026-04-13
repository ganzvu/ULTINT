import subprocess
import requests
import json
import socket
import re
import shutil
from rich.table import Table
from rich.panel import Panel

def _has_tool(name):
    return shutil.which(name) is not None

def handle_command(arg_str, console):
    args = arg_str.split()
    if not args:
        console.print("[yellow]Usage: recon <subcommand> <target>[/yellow]")
        console.print("[dim]Subcommands: scan, dns, headers, wayback[/dim]")
        return
    
    subcmd = args[0]
    data = " ".join(args[1:])
    
    if not data:
        console.print("[red]Please provide a target IP or domain.[/red]")
        return

    if subcmd == 'scan':
        _full_scan(data, console)
    elif subcmd == 'dns':
        _dns_enum(data, console)
    elif subcmd == 'headers':
        _header_analysis(data, console)
    elif subcmd == 'wayback':
        _wayback(data, console)
    else:
        console.print(f"[red]Unknown recon subcommand: {subcmd}[/red]")
        console.print("[dim]Available: scan, dns, headers, wayback[/dim]")


# ══════════════════════════════════════════════════
# Full Automated Infrastructure Scan
# ══════════════════════════════════════════════════
def _full_scan(target, console):
    """
    Automated multi-phase infrastructure reconnaissance.
    Give it an IP or domain — it runs everything.
    """
    findings = []
    
    console.print(Panel(f"[bold]Target: {target}[/bold]", title="🔭 ULTINT Infrastructure Scan", border_style="cyan"))

    # ── Phase 1: DNS Resolution ─────────────────────
    resolved_ip = None
    with console.status("[cyan]Phase 1: Resolving target...[/cyan]"):
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror:
            # Maybe it's already an IP
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                resolved_ip = target
            else:
                console.print(f"[red]Cannot resolve '{target}' to an IP address.[/red]")
                return
        
        # Reverse DNS
        try:
            reverse_dns = socket.gethostbyaddr(resolved_ip)[0]
        except (socket.herror, socket.gaierror):
            reverse_dns = "N/A"

    table = Table(title="Phase 1: Target Resolution", show_lines=True)
    table.add_column("Property", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Input", target)
    table.add_row("Resolved IP", resolved_ip)
    table.add_row("Reverse DNS", reverse_dns)
    console.print(table)

    # ── Phase 2: GeoIP Location ─────────────────────
    with console.status("[cyan]Phase 2: GeoIP lookup...[/cyan]"):
        try:
            r = requests.get(f"http://ip-api.com/json/{resolved_ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query", timeout=5)
            if r.status_code == 200:
                geo = r.json()
                if geo.get('status') == 'success':
                    table = Table(title="Phase 2: GeoIP Intelligence", show_lines=True)
                    table.add_column("Property", style="cyan")
                    table.add_column("Value", style="green")
                    table.add_row("Country", geo.get('country', 'N/A'))
                    table.add_row("Region", geo.get('regionName', 'N/A'))
                    table.add_row("City", geo.get('city', 'N/A'))
                    table.add_row("Coordinates", f"{geo.get('lat', '?')}, {geo.get('lon', '?')}")
                    table.add_row("Timezone", geo.get('timezone', 'N/A'))
                    table.add_row("ISP", geo.get('isp', 'N/A'))
                    table.add_row("Organization", geo.get('org', 'N/A'))
                    table.add_row("AS Number", geo.get('as', 'N/A'))
                    console.print(table)
                    
                    if geo.get('org'):
                        findings.append(f"🏢 Organization: {geo['org']}")
                    if geo.get('city') and geo.get('country'):
                        findings.append(f"📍 Location: {geo['city']}, {geo['country']}")
        except Exception:
            console.print("[dim]Phase 2: GeoIP lookup failed (ip-api.com unreachable).[/dim]")

    # ── Phase 3: Shodan InternetDB ──────────────────
    with console.status("[cyan]Phase 3: Shodan InternetDB (keyless)...[/cyan]"):
        try:
            r = requests.get(f"https://internetdb.shodan.io/{resolved_ip}", timeout=10)
            if r.status_code == 200:
                data = r.json()
                
                table = Table(title="Phase 3: Shodan InternetDB", show_lines=True)
                table.add_column("Category", style="cyan")
                table.add_column("Findings", style="green", overflow="fold")
                
                ports = data.get('ports', [])
                hostnames = data.get('hostnames', [])
                vulns = data.get('vulns', [])
                tags = data.get('tags', [])
                cpes = data.get('cpes', [])
                
                if ports:
                    table.add_row("Open Ports", ", ".join(map(str, ports)))
                    findings.append(f"🔓 {len(ports)} open ports: {', '.join(map(str, ports[:10]))}")
                if hostnames:
                    table.add_row("Hostnames", ", ".join(hostnames))
                if vulns:
                    table.add_row("⚠️ CVEs", "[bold red]" + ", ".join(vulns) + "[/bold red]")
                    findings.append(f"🚨 {len(vulns)} known CVEs: {', '.join(vulns[:5])}")
                if tags:
                    table.add_row("Tags", ", ".join(tags))
                if cpes:
                    table.add_row("Software (CPEs)", ", ".join(cpes[:8]) + ("..." if len(cpes) > 8 else ""))
                    findings.append(f"💻 Software stack: {', '.join(cpes[:3])}")
                    
                console.print(table)
            elif r.status_code == 404:
                console.print("[dim]Phase 3: No Shodan data for this IP.[/dim]")
        except Exception:
            console.print("[dim]Phase 3: Shodan InternetDB unreachable.[/dim]")

    # ── Phase 4: WHOIS ──────────────────────────────
    with console.status("[cyan]Phase 4: WHOIS lookup...[/cyan]"):
        whois_data = None
        if _has_tool("whois"):
            try:
                result = subprocess.run(["whois", target], capture_output=True, text=True, timeout=15)
                if result.returncode == 0 and result.stdout.strip():
                    whois_data = result.stdout
            except Exception:
                pass
        
        if not whois_data:
            # Fallback to RDAP
            try:
                r = requests.get(f"https://rdap.org/domain/{target}", timeout=10)
                if r.status_code == 200:
                    rdap = r.json()
                    parts = []
                    if rdap.get('name'):
                        parts.append(f"Name: {rdap['name']}")
                    for entity in rdap.get('entities', []):
                        roles = entity.get('roles', [])
                        handle = entity.get('handle', 'Unknown')
                        if roles:
                            parts.append(f"{', '.join(roles).title()}: {handle}")
                    if parts:
                        whois_data = "\n".join(parts)
            except Exception:
                pass
        
        if whois_data:
            # Extract key WHOIS fields instead of dumping raw text
            key_fields = ['Registrar:', 'Creation Date:', 'Updated Date:', 'Registry Expiry',
                         'Registrant Organization:', 'Registrant Country:', 'Name Server:',
                         'Domain Name:', 'DNSSEC:']
            important_lines = []
            for line in whois_data.split('\n'):
                if any(field.lower() in line.lower() for field in key_fields):
                    important_lines.append(line.strip())
            
            if important_lines:
                table = Table(title="Phase 4: WHOIS Intelligence", show_lines=True)
                table.add_column("Field", style="cyan")
                table.add_column("Value", style="green", overflow="fold")
                for line in important_lines[:15]:
                    if ':' in line:
                        k, v = line.split(':', 1)
                        table.add_row(k.strip(), v.strip())
                        if 'registrant' in k.lower() and 'org' in k.lower():
                            findings.append(f"🏢 Registrant: {v.strip()}")
                console.print(table)
            else:
                console.print(Panel(whois_data[:500], title="Phase 4: WHOIS (Raw)", border_style="dim"))
        else:
            console.print("[dim]Phase 4: WHOIS data unavailable.[/dim]")

    # ── Phase 5: HTTP Header Fingerprinting ─────────
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
        with console.status("[cyan]Phase 5: HTTP header fingerprinting...[/cyan]"):
            _header_analysis_internal(target, console, findings)
    
    # ── Phase 6: Nmap (if available) ────────────────
    if _has_tool("nmap"):
        with console.status(f"[cyan]Phase 6: Quick nmap scan (-F)...[/cyan]"):
            try:
                result = subprocess.run(["nmap", "-F", "-T4", target], capture_output=True, text=True, timeout=60)
                if result.returncode == 0 and result.stdout.strip():
                    # Parse nmap output for open ports
                    open_ports = []
                    for line in result.stdout.split('\n'):
                        if '/tcp' in line and 'open' in line:
                            open_ports.append(line.strip())
                    if open_ports:
                        table = Table(title="Phase 6: Nmap Fast Scan", show_lines=True)
                        table.add_column("Port/Protocol", style="cyan")
                        table.add_column("State", style="green")
                        table.add_column("Service", style="white")
                        for line in open_ports:
                            parts = line.split()
                            if len(parts) >= 3:
                                table.add_row(parts[0], parts[1], " ".join(parts[2:]))
                        console.print(table)
            except Exception:
                pass
    else:
        console.print("[dim]Phase 6: Skipped nmap (not installed).[/dim]")

    # ── FINAL REPORT ────────────────────────────────
    console.print()
    if findings:
        report = '\n'.join(f"  {f}" for f in findings)
        console.print(Panel(report, title="📋 RECON INTELLIGENCE SUMMARY", border_style="bold green"))
    else:
        console.print(Panel("[dim]Scan complete. No major findings.[/dim]", title="📋 Scan Complete", border_style="dim"))


# ══════════════════════════════════════════════════
# DNS Enumeration
# ══════════════════════════════════════════════════
def _dns_enum(domain, console):
    """Comprehensive DNS enumeration using system dig/nslookup and public APIs."""
    console.print(Panel(f"[bold]Target: {domain}[/bold]", title="🌐 DNS Enumeration", border_style="cyan"))
    
    findings = []
    
    # Standard record types
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    
    table = Table(title="DNS Records", show_lines=True)
    table.add_column("Type", style="cyan", min_width=6)
    table.add_column("Value", style="green", overflow="fold")
    
    for rtype in record_types:
        with console.status(f"[cyan]Querying {rtype} records...[/cyan]"):
            try:
                if _has_tool("dig"):
                    result = subprocess.run(["dig", "+short", rtype, domain], capture_output=True, text=True, timeout=10)
                    records = [r.strip() for r in result.stdout.strip().split('\n') if r.strip()]
                elif _has_tool("nslookup"):
                    result = subprocess.run(["nslookup", f"-type={rtype}", domain], capture_output=True, text=True, timeout=10)
                    records = []
                    for line in result.stdout.split('\n'):
                        if 'answer' in line.lower() or '=' in line or 'address' in line.lower():
                            records.append(line.strip())
                else:
                    # Pure Python fallback for A records
                    if rtype == 'A':
                        try:
                            ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                            records = list(set(addr[4][0] for addr in ips))
                        except Exception:
                            records = []
                    elif rtype == 'AAAA':
                        try:
                            ips = socket.getaddrinfo(domain, None, socket.AF_INET6)
                            records = list(set(addr[4][0] for addr in ips))
                        except Exception:
                            records = []
                    else:
                        records = []
                
                if records:
                    for rec in records:
                        table.add_row(rtype, rec)
                    if rtype == 'TXT':
                        for rec in records:
                            if 'spf' in rec.lower():
                                findings.append(f"📧 SPF record found: {rec[:80]}")
                            elif 'dmarc' in rec.lower():
                                findings.append(f"📧 DMARC record found")
                            elif 'v=DKIM' in rec:
                                findings.append(f"📧 DKIM record found")
                    if rtype == 'MX':
                        findings.append(f"📬 Mail servers: {', '.join(records[:3])}")
            except Exception:
                pass
    
    console.print(table)
    
    # Subdomain discovery via crt.sh (Certificate Transparency)
    with console.status("[cyan]Querying Certificate Transparency logs (crt.sh)...[/cyan]"):
        try:
            r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=15)
            if r.status_code == 200:
                certs = r.json()
                subdomains = set()
                for cert in certs:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and sub != domain and '*' not in sub:
                            subdomains.add(sub)
                
                if subdomains:
                    sorted_subs = sorted(subdomains)[:30]
                    findings.append(f"🌐 {len(subdomains)} subdomains discovered via CT logs")
                    sub_text = '\n'.join(sorted_subs)
                    if len(subdomains) > 30:
                        sub_text += f"\n\n... and {len(subdomains) - 30} more"
                    console.print(Panel(sub_text, title=f"Subdomains ({len(subdomains)} found)", border_style="magenta"))
        except Exception:
            console.print("[dim]Certificate Transparency lookup failed.[/dim]")
    
    if findings:
        report = '\n'.join(f"  {f}" for f in findings)
        console.print(Panel(report, title="📋 DNS INTELLIGENCE", border_style="bold green"))


# ══════════════════════════════════════════════════
# HTTP Header Fingerprinting
# ══════════════════════════════════════════════════
def _header_analysis(target, console, findings=None):
    """Standalone header analysis command."""
    console.print(Panel(f"[bold]Target: {target}[/bold]", title="🔍 HTTP Header Analysis", border_style="cyan"))
    f = []
    _header_analysis_internal(target, console, f)
    if f:
        report = '\n'.join(f"  {item}" for item in f)
        console.print(Panel(report, title="📋 HEADER INTELLIGENCE", border_style="bold green"))

def _header_analysis_internal(target, console, findings):
    """Fetch and analyze HTTP headers for technology stack and security posture."""
    for scheme in ['https', 'http']:
        try:
            url = f"{scheme}://{target}" if '://' not in target else target
            r = requests.get(url, timeout=10, allow_redirects=True, 
                           headers={'User-Agent': 'Mozilla/5.0 (ULTINT Recon)'})
            
            headers = dict(r.headers)
            
            table = Table(title=f"HTTP Headers ({scheme.upper()})", show_lines=True)
            table.add_column("Header", style="cyan", min_width=20)
            table.add_column("Value", style="green", overflow="fold")
            
            # Security headers to check
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'X-XSS-Protection': 'XSS Filter',
                'Permissions-Policy': 'Permissions Policy',
            }
            
            # Technology detection
            tech_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator',
                          'X-Drupal-Cache', 'X-Varnish', 'Via', 'X-Cache']
            
            for header, value in headers.items():
                style = "green"
                if header.lower() in [h.lower() for h in tech_headers]:
                    style = "bold yellow"
                    findings.append(f"💻 {header}: {value}")
                table.add_row(header, f"[{style}]{value}[/{style}]")
            
            console.print(table)
            
            # Security audit
            missing_security = []
            for sec_header, desc in security_headers.items():
                if sec_header.lower() not in [h.lower() for h in headers]:
                    missing_security.append(f"❌ Missing: {sec_header} ({desc})")
            
            if missing_security:
                findings.append(f"🛡️ {len(missing_security)} missing security headers")
                console.print(Panel('\n'.join(missing_security), 
                                  title="⚠️ Missing Security Headers", border_style="yellow"))
            
            # Check for information leakage
            if 'Server' in headers:
                findings.append(f"🖥️ Server: {headers['Server']}")
            if 'X-Powered-By' in headers:
                findings.append(f"⚙️ Powered-By: {headers['X-Powered-By']}")
            
            break  # Success, don't try the other scheme
            
        except requests.exceptions.SSLError:
            if scheme == 'https':
                findings.append("🔓 SSL/TLS error — certificate may be invalid")
                continue
        except Exception:
            if scheme == 'http':
                console.print("[dim]Phase 5: HTTP headers unavailable.[/dim]")


# ══════════════════════════════════════════════════
# Wayback Machine Ghost Endpoints
# ══════════════════════════════════════════════════
def _wayback(domain, console):
    """Pulls archived ghost endpoints from Wayback Machine CDX API."""
    console.print(Panel(f"[bold]Target: {domain}[/bold]", title="👻 Wayback Ghost Endpoints", border_style="cyan"))
    try:
        with console.status(f"[cyan]Pulling CDX Archive for {domain}...[/cyan]"):
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original,mimetype,statuscode&collapse=urlkey"
            resp = requests.get(url, timeout=30)
            
            if resp.status_code != 200:
                console.print(f"[red]Failed to reach Wayback API: HTTP {resp.status_code}[/red]")
                return
                
            data = resp.json()
            if len(data) <= 1:
                console.print(f"[yellow]No archived data found for {domain}[/yellow]")
                return
                
            junk_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.woff', 
                             '.woff2', '.ttf', '.txt', '.ico', '.js', '.map']
            
            interesting_urls = []
            for row in data[1:]:
                orig_url = row[0]
                mime = row[1]
                status = row[2]
                
                if any(orig_url.lower().endswith(ext) for ext in junk_extensions):
                    continue
                if mime in ['image/jpeg', 'image/png', 'image/gif', 'text/css', 'application/javascript']:
                    continue
                    
                interesting_urls.append(f"[{status}] {orig_url}")
                
            if not interesting_urls:
                console.print(f"[yellow]Only junk/media artifacts found for {domain}[/yellow]")
                return
                
            # Categorize by interesting patterns
            api_endpoints = [u for u in interesting_urls if '/api/' in u.lower() or '/v1/' in u.lower() or '/v2/' in u.lower()]
            admin_panels = [u for u in interesting_urls if any(p in u.lower() for p in ['/admin', '/login', '/dashboard', '/panel', '/wp-admin'])]
            
            cap = 50
            display_urls = interesting_urls[:cap]
            
            output = "\n".join(display_urls)
            if len(interesting_urls) > cap:
                output += f"\n\n... and {len(interesting_urls) - cap} more endpoints omitted."
                
            console.print(Panel(output, title=f"All Endpoints ({len(interesting_urls)} found)", border_style="cyan"))
            
            if api_endpoints:
                console.print(Panel('\n'.join(api_endpoints[:20]), title=f"🔌 API Endpoints ({len(api_endpoints)})", border_style="yellow"))
            if admin_panels:
                console.print(Panel('\n'.join(admin_panels[:20]), title=f"🔐 Admin Panels ({len(admin_panels)})", border_style="red"))
            
    except Exception as e:
        console.print(f"[bold red]Wayback Error[/bold red]: {e}")

import subprocess
import requests
import json
from rich.table import Table
from rich.panel import Panel

def get_internetdb(ip, console):
    """Hits the keyless Shodan InternetDB API"""
    try:
        with console.status(f"[cyan]Querying InternetDB for {ip}...[/cyan]"):
            resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
            
            if resp.status_code == 404:
                console.print(f"[yellow]No Shodan data found for IP: {ip}[/yellow]")
                return
            elif resp.status_code != 200:
                console.print(f"[red]Error contacting InternetDB: HTTP {resp.status_code}[/red]")
                return
                
            data = resp.json()
            
            table = Table(title=f"Shodan InternetDB Scan: {ip}", show_lines=True)
            table.add_column("Category", style="cyan", justify="right")
            table.add_column("Findings", style="green")
            
            table.add_row("Open Ports", ", ".join(map(str, data.get('ports', []))))
            if data.get('hostnames'):
                table.add_row("Hostnames", ", ".join(data['hostnames']))
            if data.get('vulns'):
                table.add_row("Vulnerabilities (CVEs)", ", ".join(data['vulns']))
            if data.get('tags'):
                table.add_row("Tags", ", ".join(data['tags']))
            if data.get('cpes'):
                # Truncate CPEs if it's too massive
                cpes = data['cpes']
                cpe_str = ", ".join(cpes[:5]) + ("..." if len(cpes) > 5 else "")
                table.add_row("CPEs", cpe_str)
                
            console.print(table)
    except Exception as e:
        console.print(f"[bold red]IDB Error[/bold red]: {e}")

def get_wayback(domain, console):
    """Pulls archived ghost endpoints from Wayback Machine CDX API"""
    try:
        with console.status(f"[cyan]Pulling CDX Archive for {domain}...[/cyan]"):
            # We want unique URLs, excluding typical junk (images, css, js)
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original,mimetype,statuscode&collapse=urlkey"
            resp = requests.get(url, timeout=30)
            
            if resp.status_code != 200:
                console.print(f"[red]Failed to reach Wayback API: HTTP {resp.status_code}[/red]")
                return
                
            data = resp.json()
            if len(data) <= 1:
                console.print(f"[yellow]No archived data found for {domain}[/yellow]")
                return
                
            junk_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.svg', '.css', '.woff', '.woff2', '.ttf', '.txt']
            
            interesting_urls = []
            # data[0] is the header row
            for row in data[1:]:
                orig_url = row[0]
                mime = row[1]
                status = row[2]
                
                # Exclude obvious media/styling
                if any(orig_url.lower().endswith(ext) for ext in junk_extensions):
                    continue
                if mime in ['image/jpeg', 'image/png', 'image/gif', 'text/css']:
                    continue
                    
                interesting_urls.append(f"[{status}] {orig_url}")
                
            if not interesting_urls:
                console.print(f"[yellow]Only junk/media artifacts found for {domain}[/yellow]")
                return
                
            # Cap at 50 to avoid blowing up the terminal
            cap = 50
            display_urls = interesting_urls[:cap]
            
            output = "\n".join(display_urls)
            if len(interesting_urls) > cap:
                output += f"\n\n... and {len(interesting_urls) - cap} more endpoints omitted."
                
            console.print(Panel(output, title=f"Wayback Ghost Endpoints: {domain}", border_style="cyan"))
            
    except Exception as e:
        console.print(f"[bold red]Wayback Error[/bold red]: {e}")

def handle_command(arg_str, console):
    args = arg_str.split()
    valid_cmds = ["whois", "nmap", "idb", "wayback"]
    
    if not args:
        console.print(f"[yellow]Please provide a subcommand: {', '.join(valid_cmds)}[/yellow]")
        return
    
    subcmd = args[0]
    data = " ".join(args[1:])
    
    if not data:
        console.print("[red]Please provide a target IP or domain.[/red]")
        return

    if subcmd == 'whois':
        try:
            with console.status(f"[cyan]Running whois on {data}...[/cyan]"):
                result = subprocess.run(["whois", data], capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    console.print(Panel(result.stdout, title=f"WHOIS: {data}", border_style="green"))
                else:
                    console.print("[red]Local 'whois' failed. Trying RDAP API...[/red]")
                    resp = requests.get(f"https://rdap.org/domain/{data}")
                    if resp.status_code == 200:
                        console.print(Panel(str(resp.json()), title=f"RDAP: {data}", border_style="green"))
                    else:
                        console.print(f"[red]API failed: {resp.status_code}[/red]")
        except FileNotFoundError:
            console.print("[yellow]'whois' tool not found locally.[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error[/bold red]: {e}")

    elif subcmd == 'nmap':
        try:
            with console.status(f"[cyan]Running targeted nmap -F on {data}...[/cyan]"):
                result = subprocess.run(["nmap", "-F", data], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    console.print(Panel(result.stdout, title=f"Targeted NMAP: {data}", border_style="cyan"))
                else:
                    console.print(f"[red]nmap error: {result.stderr}[/red]")
        except FileNotFoundError:
            console.print("[yellow]'nmap' tool not found locally. Please install Nmap.[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error[/bold red]: {e}")
            
    elif subcmd == 'idb':
        get_internetdb(data, console)
        
    elif subcmd == 'wayback':
        get_wayback(data, console)
        
    else:
        console.print(f"[red]Unknown recon subcommand: {subcmd}[/red]")

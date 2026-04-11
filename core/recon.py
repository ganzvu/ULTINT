import subprocess
import requests
from rich.table import Table
from rich.panel import Panel

def handle_command(arg_str, console):
    args = arg_str.split()
    if not args:
        console.print("[yellow]Please provide a subcommand (whois, nmap)[/yellow]")
        return
    
    subcmd = args[0]
    data = " ".join(args[1:])
    
    if not data:
        console.print("[red]Please provide a target.[/red]")
        return

    if subcmd == 'whois':
        # Using a public API for WHOIS to avoid needing local 'whois' tool necessarily, or use subprocess.
        # Let's try subprocess first, fallback to API
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
            console.print("[yellow]'whois' tool not found locally. Please install it or we will fallback to API eventually.[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error[/bold red]: {e}")

    elif subcmd == 'nmap':
        try:
            with console.status(f"[cyan]Running nmap -F on {data}...[/cyan]"):
                result = subprocess.run(["nmap", "-F", data], capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    console.print(Panel(result.stdout, title=f"Fast NMAP: {data}", border_style="cyan"))
                else:
                    console.print(f"[red]nmap error: {result.stderr}[/red]")
        except FileNotFoundError:
            console.print("[yellow]'nmap' tool not found locally. Please install Nmap.[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error[/bold red]: {e}")
    else:
        console.print(f"[red]Unknown recon subcommand: {subcmd}[/red]")

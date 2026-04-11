import requests
import json
from rich.table import Table

def handle_command(arg_str, console):
    args = arg_str.split()
    if not args:
        console.print("[yellow]Please provide a subcommand (username)[/yellow]")
        return
    
    subcmd = args[0]
    target = " ".join(args[1:])
    
    if not target:
        console.print("[red]Please provide a target username.[/red]")
        return
        
    if subcmd == 'username':
        # This is a mock/lite version of Sherlock logic.
        # In a real tool, it would parse a large JSON of sites.
        sites = {
            "GitHub": f"https://github.com/{target}",
            "Twitter (API needed)": f"https://twitter.com/{target}",
            "Instagram": f"https://www.instagram.com/{target}/"
        }
        
        table = Table(title=f"Username check: {target}", show_lines=True)
        table.add_column("Platform", style="blue")
        table.add_column("URL", overflow="fold")
        table.add_column("Status", style="bold")
        
        with console.status(f"[cyan]Checking platforms for {target}...[/cyan]"):
            for site, url in sites.items():
                if "API needed" in site or "Instagram" in site:
                    # Some sites block basic requests
                    table.add_row(site, url, "[yellow]? (Blocked/Requires API)[/yellow]")
                    continue
                    
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        table.add_row(site, url, "[green]Found![/green]")
                    elif resp.status_code == 404:
                        table.add_row(site, url, "[red]Not Found[/red]")
                    else:
                        table.add_row(site, url, f"[yellow]{resp.status_code}[/yellow]")
                except requests.RequestException:
                    table.add_row(site, url, "[red]Error[/red]")
                    
            console.print(table)
    else:
        console.print(f"[red]Unknown social subcommand: {subcmd}[/red]")

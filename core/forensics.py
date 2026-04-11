import subprocess
from rich.table import Table
from rich.panel import Panel

def handle_command(arg_str, console):
    args = arg_str.split()
    if not args:
        console.print("[yellow]Please provide a subcommand (exif, strings)[/yellow]")
        return
    
    subcmd = args[0]
    target_file = " ".join(args[1:])
    
    if not target_file:
        console.print("[red]Please provide a target file path.[/red]")
        return
        
    if subcmd == 'exif':
        try:
            with console.status(f"[cyan]Extracting EXIF data from {target_file}...[/cyan]"):
                result = subprocess.run(["exiftool", target_file], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    table = Table(title=f"EXIF Metadata: {target_file}")
                    table.add_column("Tag", style="cyan")
                    table.add_column("Value", style="green")
                    for line in result.stdout.split('\n'):
                        if ':' in line:
                            parts = line.split(':', 1)
                            table.add_row(parts[0].strip(), parts[1].strip())
                    console.print(table)
                else:
                    console.print(f"[red]exiftool error: {result.stderr}[/red]")
        except FileNotFoundError:
            console.print("[yellow]'exiftool' not found locally. Please install it (e.g. `apt install libimage-exiftool-perl` or windows equivalent).[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error[/bold red]: {e}")

    elif subcmd == 'strings':
        try:
            with console.status(f"[cyan]Extracting strings from {target_file}...[/cyan]"):
                # On Windows, 'strings' might be sysinternals strings. On linux, it's gnu strings.
                result = subprocess.run(["strings", target_file], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    preview = '\n'.join(lines[:20])
                    footer = f"... [dim]and {len(lines) - 20} more lines[/dim]" if len(lines) > 20 else ""
                    console.print(Panel(preview + "\n" + footer, title=f"Strings (Top 20): {target_file}", border_style="blue"))
                else:
                    console.print(f"[red]strings error: {result.stderr}[/red]")
        except FileNotFoundError:
            console.print("[yellow]'strings' utility not found on path.[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error[/bold red]: {e}")
    else:
        console.print(f"[red]Unknown forensics subcommand: {subcmd}[/red]")

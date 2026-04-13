import subprocess
import os
import hashlib
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich.text import Text

def handle_command(arg_str, console):
    args = arg_str.split()
    if not args:
        console.print("[yellow]Usage: forensics <subcommand> <file> [options][/yellow]")
        console.print("[dim]Subcommands: exif, strings, steghide, binwalk, filetype, hexdump, hash, entropy[/dim]")
        return
    
    subcmd = args[0]
    
    # --- Steghide requires special argument parsing ---
    if subcmd == 'steghide':
        _steghide(args[1:], console)
        return

    target_file = " ".join(args[1:])
    
    if not target_file:
        console.print("[red]Please provide a target file path.[/red]")
        return
        
    if subcmd == 'exif':
        _exif(target_file, console)
    elif subcmd == 'strings':
        _strings(target_file, console)
    elif subcmd == 'binwalk':
        _binwalk(target_file, console)
    elif subcmd in ['filetype', 'file']:
        _filetype(target_file, console)
    elif subcmd in ['hexdump', 'hex', 'xxd']:
        _hexdump(target_file, console)
    elif subcmd == 'hash':
        _hash_file(target_file, console)
    elif subcmd == 'entropy':
        _entropy(target_file, console)
    else:
        console.print(f"[red]Unknown forensics subcommand: {subcmd}[/red]")
        console.print("[dim]Available: exif, strings, steghide, binwalk, filetype, hexdump, hash, entropy[/dim]")


# ══════════════════════════════════════════
# EXIF Metadata Extraction
# ══════════════════════════════════════════
def _exif(target_file, console):
    try:
        with console.status(f"[cyan]Extracting EXIF data from {target_file}...[/cyan]"):
            result = subprocess.run(["exiftool", target_file], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                table = Table(title=f"EXIF Metadata: {target_file}", show_lines=True)
                table.add_column("Tag", style="cyan", min_width=25)
                table.add_column("Value", style="green", overflow="fold")
                
                # Highlight GPS and suspicious fields
                highlight_tags = ['gps', 'location', 'latitude', 'longitude', 'comment', 'author', 'creator', 'software']
                for line in result.stdout.split('\n'):
                    if ':' in line:
                        parts = line.split(':', 1)
                        tag = parts[0].strip()
                        val = parts[1].strip()
                        style = "bold yellow" if any(h in tag.lower() for h in highlight_tags) else "green"
                        table.add_row(tag, f"[{style}]{val}[/{style}]")
                console.print(table)
            else:
                console.print(f"[red]exiftool error: {result.stderr}[/red]")
    except FileNotFoundError:
        console.print("[yellow]'exiftool' not found. Install: `apt install libimage-exiftool-perl` (Linux) or download from exiftool.org (Windows).[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error[/bold red]: {e}")


# ══════════════════════════════════════════
# Strings Extraction
# ══════════════════════════════════════════
def _strings(target_file, console):
    try:
        with console.status(f"[cyan]Extracting strings from {target_file}...[/cyan]"):
            result = subprocess.run(["strings", target_file], capture_output=True, text=True, timeout=15)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                
                # Auto-detect interesting patterns (flags, URLs, emails)
                flag_patterns = []
                for i, line in enumerate(lines):
                    l_lower = line.lower()
                    if any(p in l_lower for p in ['flag{', 'ctf{', 'key{', 'secret', 'password', 'http://', 'https://', '@', 'base64']):
                        flag_patterns.append(f"[bold yellow]L{i+1}: {line}[/bold yellow]")
                
                preview = '\n'.join(lines[:30])
                footer = f"\n... [dim]and {len(lines) - 30} more lines[/dim]" if len(lines) > 30 else ""
                console.print(Panel(preview + footer, title=f"Strings (Top 30): {target_file}", border_style="blue"))
                
                if flag_patterns:
                    console.print(Panel('\n'.join(flag_patterns[:15]), title="⚠️ Suspicious Patterns Detected", border_style="yellow"))
            else:
                console.print(f"[red]strings error: {result.stderr}[/red]")
    except FileNotFoundError:
        console.print("[yellow]'strings' utility not found on path.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error[/bold red]: {e}")


# ══════════════════════════════════════════
# Steganography — Steghide
# ══════════════════════════════════════════
def _steghide(args, console):
    """
    Usage:
        forensics steghide extract <file> [passphrase]   — Extract hidden data
        forensics steghide info <file>                    — Show embed info
        forensics steghide embed <cover> <secret> [pass]  — Embed data
    """
    if len(args) < 2:
        console.print("[yellow]Usage:[/yellow]")
        console.print("  forensics steghide extract <file> [passphrase]")
        console.print("  forensics steghide info <file>")
        console.print("  forensics steghide embed <cover_file> <secret_file> [passphrase]")
        return

    action = args[0]
    
    if action == 'info':
        target = args[1]
        try:
            with console.status(f"[cyan]Analyzing steganographic profile of {target}...[/cyan]"):
                result = subprocess.run(
                    ["steghide", "info", target, "-f"],
                    capture_output=True, text=True, timeout=15,
                    input="\n"  # auto-answer no to extract prompt
                )
                output = result.stdout + result.stderr
                console.print(Panel(output.strip(), title=f"Steghide Info: {target}", border_style="magenta"))
        except FileNotFoundError:
            console.print("[yellow]'steghide' not found. Install: `apt install steghide`[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error[/bold red]: {e}")

    elif action == 'extract':
        target = args[1]
        passphrase = args[2] if len(args) > 2 else ""
        try:
            cmd = ["steghide", "extract", "-sf", target, "-f"]
            if passphrase:
                cmd += ["-p", passphrase]
            else:
                cmd += ["-p", ""]  # Try empty passphrase first

            with console.status(f"[cyan]Attempting steghide extraction from {target}...[/cyan]"):
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                output = result.stdout + result.stderr
                if "wrote extracted data" in output.lower() or result.returncode == 0:
                    console.print(Panel(f"[bold green]{output.strip()}[/bold green]", title="🔓 Steghide Extraction Success!", border_style="green"))
                else:
                    console.print(Panel(f"[yellow]{output.strip()}[/yellow]", title="Steghide Extraction", border_style="yellow"))
                    if not passphrase:
                        console.print("[dim]Tip: Try providing a passphrase: forensics steghide extract <file> <passphrase>[/dim]")
        except FileNotFoundError:
            console.print("[yellow]'steghide' not found. Install: `apt install steghide`[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error[/bold red]: {e}")

    elif action == 'embed':
        if len(args) < 3:
            console.print("[red]Usage: forensics steghide embed <cover_file> <secret_file> [passphrase][/red]")
            return
        cover = args[1]
        secret = args[2]
        passphrase = args[3] if len(args) > 3 else ""
        try:
            cmd = ["steghide", "embed", "-cf", cover, "-ef", secret, "-f"]
            if passphrase:
                cmd += ["-p", passphrase]
            else:
                cmd += ["-p", ""]
            with console.status(f"[cyan]Embedding {secret} into {cover}...[/cyan]"):
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                output = result.stdout + result.stderr
                console.print(Panel(output.strip(), title="Steghide Embed", border_style="magenta"))
        except FileNotFoundError:
            console.print("[yellow]'steghide' not found. Install: `apt install steghide`[/yellow]")
        except Exception as e:
            console.print(f"[bold red]Error[/bold red]: {e}")
    else:
        console.print(f"[red]Unknown steghide action: {action}. Use: info, extract, embed[/red]")


# ══════════════════════════════════════════
# Binwalk — Firmware / Embedded File Carving
# ══════════════════════════════════════════
def _binwalk(target_file, console):
    try:
        with console.status(f"[cyan]Running binwalk signature scan on {target_file}...[/cyan]"):
            result = subprocess.run(["binwalk", target_file], capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                table = Table(title=f"Binwalk Scan: {target_file}", show_lines=True)
                table.add_column("Offset", style="cyan", min_width=12)
                table.add_column("Type", style="green")
                table.add_column("Description", style="white", overflow="fold")
                
                for line in result.stdout.strip().split('\n'):
                    # Skip header lines
                    if line.startswith('DECIMAL') or line.startswith('---'):
                        continue
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        table.add_row(parts[0], parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else "")
                    elif parts:
                        table.add_row(parts[0], "", " ".join(parts[1:]) if len(parts) > 1 else "")
                console.print(table)
                console.print("[dim]Tip: Run `binwalk -e <file>` manually to auto-extract embedded files.[/dim]")
            else:
                console.print(f"[yellow]No embedded signatures found in {target_file}.[/yellow]")
    except FileNotFoundError:
        console.print("[yellow]'binwalk' not found. Install: `apt install binwalk` or `pip install binwalk`[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error[/bold red]: {e}")


# ══════════════════════════════════════════
# File Type Identification (magic bytes)
# ══════════════════════════════════════════
def _filetype(target_file, console):
    try:
        with console.status(f"[cyan]Identifying file type for {target_file}...[/cyan]"):
            # Run `file` command for magic byte analysis
            result = subprocess.run(["file", "-b", target_file], capture_output=True, text=True, timeout=10)
            file_type = result.stdout.strip() if result.returncode == 0 else "Unknown"
            
            # Also get MIME type
            result_mime = subprocess.run(["file", "-b", "--mime-type", target_file], capture_output=True, text=True, timeout=10)
            mime = result_mime.stdout.strip() if result_mime.returncode == 0 else "Unknown"
            
            # File size
            size = os.path.getsize(target_file)
            if size > 1048576:
                size_str = f"{size / 1048576:.2f} MB"
            elif size > 1024:
                size_str = f"{size / 1024:.2f} KB"
            else:
                size_str = f"{size} bytes"
            
            # Read magic bytes (first 16 bytes hex)
            with open(target_file, 'rb') as f:
                magic = f.read(16)
            magic_hex = ' '.join(f'{b:02x}' for b in magic)
            
            table = Table(title=f"File Analysis: {target_file}", show_lines=True)
            table.add_column("Property", style="cyan", min_width=15)
            table.add_column("Value", style="green", overflow="fold")
            table.add_row("File Type", file_type)
            table.add_row("MIME Type", mime)
            table.add_row("File Size", size_str)
            table.add_row("Magic Bytes", magic_hex)
            
            # Check for extension mismatch (common CTF trick)
            ext = os.path.splitext(target_file)[1].lower()
            warned = False
            if ext in ['.jpg', '.jpeg'] and 'jpeg' not in file_type.lower():
                table.add_row("⚠️ WARNING", "[bold red]Extension says JPEG but magic bytes disagree![/bold red]")
                warned = True
            elif ext == '.png' and 'png' not in file_type.lower():
                table.add_row("⚠️ WARNING", "[bold red]Extension says PNG but magic bytes disagree![/bold red]")
                warned = True
            elif ext == '.pdf' and 'pdf' not in file_type.lower():
                table.add_row("⚠️ WARNING", "[bold red]Extension says PDF but magic bytes disagree![/bold red]")
                warned = True
            
            console.print(table)
    except FileNotFoundError:
        if not os.path.exists(target_file):
            console.print(f"[red]File not found: {target_file}[/red]")
        else:
            console.print("[yellow]'file' command not found on path.[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error[/bold red]: {e}")


# ══════════════════════════════════════════
# Hex Dump (first 256 bytes)
# ══════════════════════════════════════════
def _hexdump(target_file, console):
    try:
        with open(target_file, 'rb') as f:
            data = f.read(256)
        
        lines = []
        for offset in range(0, len(data), 16):
            chunk = data[offset:offset+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"[cyan]{offset:08x}[/cyan]  {hex_part:<48}  [green]{ascii_part}[/green]")
        
        console.print(Panel('\n'.join(lines), title=f"Hex Dump (first 256 bytes): {target_file}", border_style="blue"))
    except FileNotFoundError:
        console.print(f"[red]File not found: {target_file}[/red]")
    except Exception as e:
        console.print(f"[bold red]Error[/bold red]: {e}")


# ══════════════════════════════════════════
# File Hashing (integrity / lookup)
# ══════════════════════════════════════════
def _hash_file(target_file, console):
    try:
        with console.status(f"[cyan]Computing file hashes for {target_file}...[/cyan]"):
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(target_file, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            
            table = Table(title=f"File Hashes: {target_file}", show_lines=True)
            table.add_column("Algorithm", style="cyan", min_width=10)
            table.add_column("Hash", style="green")
            table.add_row("MD5", md5.hexdigest())
            table.add_row("SHA-1", sha1.hexdigest())
            table.add_row("SHA-256", sha256.hexdigest())
            console.print(table)
            console.print("[dim]Tip: Search these hashes on VirusTotal to check for known malware.[/dim]")
    except FileNotFoundError:
        console.print(f"[red]File not found: {target_file}[/red]")
    except Exception as e:
        console.print(f"[bold red]Error[/bold red]: {e}")


# ══════════════════════════════════════════
# Entropy Analysis (detect encryption/compression)
# ══════════════════════════════════════════
def _entropy(target_file, console):
    import math
    try:
        with open(target_file, 'rb') as f:
            data = f.read()
        
        if not data:
            console.print("[red]File is empty.[/red]")
            return
        
        # Shannon entropy calculation
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        
        # Visual bar
        bar_len = 40
        filled = int((entropy / 8.0) * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)
        
        # Interpretation
        if entropy > 7.5:
            verdict = "[bold red]Very High — Likely encrypted or compressed data[/bold red]"
        elif entropy > 6.0:
            verdict = "[bold yellow]High — Possibly compressed (ZIP, GZIP, etc.)[/bold yellow]"
        elif entropy > 4.0:
            verdict = "[bold green]Medium — Typical structured data (executables, documents)[/bold green]"
        else:
            verdict = "[bold cyan]Low — Likely plaintext or repetitive data[/bold cyan]"
        
        table = Table(title=f"Entropy Analysis: {target_file}", show_lines=True)
        table.add_column("Property", style="cyan", min_width=15)
        table.add_column("Value", style="green", overflow="fold")
        table.add_row("File Size", f"{len(data):,} bytes")
        table.add_row("Shannon Entropy", f"{entropy:.4f} / 8.0 bits")
        table.add_row("Entropy Bar", bar)
        table.add_row("Verdict", verdict)
        console.print(table)
    except FileNotFoundError:
        console.print(f"[red]File not found: {target_file}[/red]")
    except Exception as e:
        console.print(f"[bold red]Error[/bold red]: {e}")

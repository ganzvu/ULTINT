import subprocess
import os
import hashlib
import math
import shutil
from rich.table import Table
from rich.panel import Panel

def handle_command(arg_str, console):
    args = arg_str.split()
    if not args:
        console.print("[yellow]Usage: forensics <subcommand> <file>[/yellow]")
        console.print("[dim]Subcommands: analyze, stegcrack[/dim]")
        return
    
    subcmd = args[0]
    target_file = " ".join(args[1:])
    
    if not target_file:
        console.print("[red]Please provide a target file path.[/red]")
        return
    
    if not os.path.exists(target_file):
        console.print(f"[red]File not found: {target_file}[/red]")
        return

    if subcmd == 'analyze':
        _full_analysis(target_file, console)
    elif subcmd == 'stegcrack':
        _steg_bruteforce(target_file, console)
    else:
        console.print(f"[red]Unknown subcommand: {subcmd}. Use: analyze, stegcrack[/red]")


def _has_tool(name):
    """Check if a system tool is available on PATH."""
    return shutil.which(name) is not None


def _run(cmd, timeout=15, stdin_data=None):
    """Run a subprocess and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin_data)
        return result.returncode == 0, result.stdout, result.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False, "", ""


# ══════════════════════════════════════════════════
# Full Automated Analysis Pipeline
# ══════════════════════════════════════════════════
def _full_analysis(target_file, console):
    """
    The core value of ULTINT forensics: throw a file at it and let
    the engine automatically run every relevant analysis tool in sequence,
    surfacing only actionable intelligence.
    """
    findings = []  # Collect important discoveries to summarize at end
    
    console.print(Panel(f"[bold]Target: {target_file}[/bold]", title="🔬 ULTINT Forensic Analysis", border_style="cyan"))

    # ── Phase 1: File Identity ──────────────────────
    with console.status("[cyan]Phase 1: Identifying file...[/cyan]"):
        size = os.path.getsize(target_file)
        size_str = f"{size / 1048576:.2f} MB" if size > 1048576 else f"{size / 1024:.2f} KB" if size > 1024 else f"{size} bytes"
        
        # Magic bytes
        with open(target_file, 'rb') as f:
            magic = f.read(16)
        magic_hex = ' '.join(f'{b:02x}' for b in magic)
        
        # file command
        file_type = "Unknown"
        mime = "Unknown"
        if _has_tool("file"):
            ok, out, _ = _run(["file", "-b", target_file])
            if ok: file_type = out.strip()
            ok, out, _ = _run(["file", "-b", "--mime-type", target_file])
            if ok: mime = out.strip()
        
        # Extension mismatch detection
        ext = os.path.splitext(target_file)[1].lower()
        mismatch = False
        real_ext = ""
        if 'jpeg' in file_type.lower() or 'jpg' in file_type.lower():
            real_ext = ".jpg"
        elif 'png' in file_type.lower():
            real_ext = ".png"
        elif 'pdf' in file_type.lower():
            real_ext = ".pdf"
        elif 'zip' in file_type.lower():
            real_ext = ".zip"
        elif 'gif' in file_type.lower():
            real_ext = ".gif"
            
        if real_ext and ext and ext != real_ext and ext not in [real_ext]:
            mismatch = True
            findings.append(f"⚠️ EXTENSION MISMATCH: File is actually {real_ext.upper()} but named {ext}")
    
    table = Table(title="Phase 1: File Identity", show_lines=True)
    table.add_column("Property", style="cyan", min_width=15)
    table.add_column("Value", style="green", overflow="fold")
    table.add_row("Size", size_str)
    table.add_row("Type", file_type)
    table.add_row("MIME", mime)
    table.add_row("Magic Bytes", magic_hex)
    if mismatch:
        table.add_row("⚠️ WARNING", f"[bold red]Extension '{ext}' does not match detected type '{real_ext}'![/bold red]")
    console.print(table)

    # ── Phase 2: Hashing ────────────────────────────
    with console.status("[cyan]Phase 2: Computing hashes...[/cyan]"):
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()
        with open(target_file, 'rb') as f:
            while True:
                chunk = f.read(65536)
                if not chunk: break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
    
    table = Table(title="Phase 2: File Hashes", show_lines=True)
    table.add_column("Algorithm", style="cyan")
    table.add_column("Hash", style="green")
    table.add_row("MD5", md5.hexdigest())
    table.add_row("SHA-1", sha1.hexdigest())
    table.add_row("SHA-256", sha256.hexdigest())
    console.print(table)

    # ── Phase 3: Entropy ────────────────────────────
    with console.status("[cyan]Phase 3: Entropy analysis...[/cyan]"):
        with open(target_file, 'rb') as f:
            data = f.read()
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / len(data)
                entropy -= p * math.log2(p)
        
        bar_len = 40
        filled = int((entropy / 8.0) * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)
        
        if entropy > 7.5:
            verdict = "Very High — Likely encrypted or compressed"
            findings.append("🔒 High entropy detected: file may contain encrypted/compressed payload")
        elif entropy > 6.0:
            verdict = "High — Possibly compressed (ZIP, GZIP)"
        elif entropy > 4.0:
            verdict = "Medium — Structured data"
        else:
            verdict = "Low — Plaintext or repetitive data"
   
    console.print(f"  [cyan]Entropy:[/cyan] {entropy:.4f}/8.0  {bar}  [dim]{verdict}[/dim]")

    # ── Phase 4: EXIF (images only) ─────────────────
    is_image = any(x in mime.lower() for x in ['image', 'jpeg', 'png', 'gif', 'tiff', 'bmp'])
    
    if is_image and _has_tool("exiftool"):
        with console.status("[cyan]Phase 4: Extracting EXIF metadata...[/cyan]"):
            ok, out, _ = _run(["exiftool", target_file])
            if ok and out.strip():
                table = Table(title="Phase 4: EXIF Metadata", show_lines=True)
                table.add_column("Tag", style="cyan", min_width=25)
                table.add_column("Value", style="green", overflow="fold")
                
                highlight_tags = ['gps', 'location', 'latitude', 'longitude', 'comment', 
                                  'author', 'creator', 'software', 'description', 'subject', 'title']
                for line in out.split('\n'):
                    if ':' in line:
                        parts = line.split(':', 1)
                        tag, val = parts[0].strip(), parts[1].strip()
                        if any(h in tag.lower() for h in highlight_tags):
                            findings.append(f"📍 EXIF '{tag}': {val}")
                            table.add_row(f"[bold yellow]{tag}[/bold yellow]", f"[bold yellow]{val}[/bold yellow]")
                        else:
                            table.add_row(tag, val)
                console.print(table)
    elif is_image:
        console.print("[dim]Phase 4: Skipped EXIF (exiftool not installed)[/dim]")

    # ── Phase 5: Steganography Auto-Crack ───────────
    steg_compatible = any(x in mime.lower() for x in ['jpeg', 'jpg', 'bmp', 'wav', 'au'])
    
    if steg_compatible and _has_tool("steghide"):
        console.print()
        with console.status("[cyan]Phase 5: Attempting steghide extraction (common passphrases)...[/cyan]"):
            common_passes = ["", "password", "123456", "secret", "admin", "flag", "ctf",
                             "hidden", "stego", "pass", "steghide", "test", "1234",
                             os.path.splitext(os.path.basename(target_file))[0],  # filename as password
                             os.path.splitext(os.path.basename(target_file))[0].lower()]
            
            for pw in common_passes:
                cmd = ["steghide", "extract", "-sf", target_file, "-p", pw, "-f"]
                ok, out, err = _run(cmd)
                combined = out + err
                if ok and "wrote extracted data" in combined.lower():
                    # Find what file was extracted
                    for word in combined.split():
                        if '.' in word and word != target_file:
                            extracted = word.strip('"').strip("'")
                            break
                    else:
                        extracted = "extracted data"
                    
                    pw_display = f"'{pw}'" if pw else "(empty passphrase)"
                    findings.append(f"🔓 STEGHIDE: Hidden data extracted with passphrase {pw_display}!")
                    console.print(Panel(
                        f"[bold green]Hidden data extracted![/bold green]\n"
                        f"Passphrase: {pw_display}\n"
                        f"Output: {combined.strip()}",
                        title="🔓 Phase 5: Steghide — DATA FOUND!", border_style="green"))
                    
                    # Auto-read the extracted file if it's text
                    if os.path.exists(extracted):
                        try:
                            with open(extracted, 'r', errors='ignore') as ef:
                                content = ef.read(1024)
                            if content.strip():
                                console.print(Panel(content.strip(), title=f"Contents of {extracted}", border_style="green"))
                                findings.append(f"📄 Extracted content: {content.strip()[:200]}")
                        except Exception:
                            pass
                    break
            else:
                console.print("[dim]Phase 5: Steghide — no data found with common passphrases.[/dim]")
                console.print("[dim]  Tip: Run 'forensics stegcrack <file>' for a full dictionary attack.[/dim]")
    elif steg_compatible:
        console.print("[dim]Phase 5: Skipped steghide (not installed — apt install steghide)[/dim]")

    # ── Phase 6: Binwalk Embedded Files ─────────────
    if _has_tool("binwalk"):
        with console.status("[cyan]Phase 6: Scanning for embedded files...[/cyan]"):
            ok, out, _ = _run(["binwalk", target_file])
            if ok and out.strip():
                lines = [l for l in out.strip().split('\n') if l and not l.startswith('DECIMAL') and not l.startswith('---')]
                if len(lines) > 1:  # More than just the file itself
                    findings.append(f"📦 Binwalk found {len(lines)} embedded signatures")
                    table = Table(title="Phase 6: Embedded Signatures", show_lines=True)
                    table.add_column("Offset", style="cyan")
                    table.add_column("Description", style="green", overflow="fold")
                    for line in lines:
                        parts = line.split(None, 2)
                        if len(parts) >= 3:
                            table.add_row(parts[0], parts[2])
                        elif parts:
                            table.add_row(parts[0], " ".join(parts[1:]))
                    console.print(table)
    else:
        console.print("[dim]Phase 6: Skipped binwalk (not installed)[/dim]")

    # ── Phase 7: Strings Intelligence ───────────────
    if _has_tool("strings"):
        with console.status("[cyan]Phase 7: Extracting strings intelligence...[/cyan]"):
            ok, out, _ = _run(["strings", target_file])
            if ok:
                lines = out.split('\n')
                # Auto-detect interesting patterns
                patterns = {
                    'flags': [], 'urls': [], 'emails': [], 'passwords': [],
                    'base64': [], 'hidden_text': []
                }
                for line in lines:
                    l = line.strip()
                    if not l: continue
                    ll = l.lower()
                    if any(p in ll for p in ['flag{', 'ctf{', 'key{', 'picoctf{', 'htb{']):
                        patterns['flags'].append(l)
                    elif any(p in ll for p in ['http://', 'https://', 'ftp://']):
                        patterns['urls'].append(l)
                    elif '@' in l and '.' in l and len(l) < 100:
                        patterns['emails'].append(l)
                    elif any(p in ll for p in ['password', 'passwd', 'secret', 'credential']):
                        patterns['passwords'].append(l)

                intel_found = False
                for category, items in patterns.items():
                    if items:
                        intel_found = True
                        findings.append(f"🔍 Strings: Found {len(items)} {category}")
                        for item in items[:5]:
                            console.print(f"  [bold yellow]{category.upper()}:[/bold yellow] {item}")
                
                if not intel_found:
                    console.print(f"[dim]Phase 7: {len(lines)} strings extracted, no obvious flags/URLs found.[/dim]")

    # ── FINAL REPORT ────────────────────────────────
    console.print()
    if findings:
        report = '\n'.join(f"  {f}" for f in findings)
        console.print(Panel(report, title="📋 INTELLIGENCE SUMMARY", border_style="bold green"))
    else:
        console.print(Panel("[dim]No significant findings. File appears clean.[/dim]", 
                           title="📋 Analysis Complete", border_style="dim"))


# ══════════════════════════════════════════════════
# Steghide Dictionary Brute-Force
# ══════════════════════════════════════════════════
def _steg_bruteforce(target_file, console):
    """
    Run steghide extraction against a wordlist (rockyou).
    This is the deep-dive when the automated Phase 5 common passwords fail.
    """
    if not _has_tool("steghide"):
        console.print("[red]'steghide' not found on system. Install: `apt install steghide`[/red]")
        return
    
    # Check MIME compatibility
    if _has_tool("file"):
        ok, out, _ = _run(["file", "-b", "--mime-type", target_file])
        mime = out.strip() if ok else ""
        if not any(x in mime.lower() for x in ['jpeg', 'jpg', 'bmp', 'wav', 'au']):
            console.print(f"[yellow]Warning: steghide only supports JPEG, BMP, WAV, AU files. Detected: {mime}[/yellow]")
            console.print("[dim]Continuing anyway...[/dim]")
    
    wordlist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    wordlist_path = os.path.join(wordlist_dir, 'rockyou.txt')
    
    if not os.path.exists(wordlist_path):
        console.print("[red]RockYou wordlist not found at data/rockyou.txt[/red]")
        console.print("[dim]Run 'crypto crack <any_hash>' first to auto-download it.[/dim]")
        return
    
    console.print(f"[cyan]Brute-forcing steghide passphrase on {target_file}...[/cyan]")
    
    tried = 0
    with open(wordlist_path, 'r', encoding='latin-1') as f:
        for line in f:
            pw = line.rstrip('\n')
            if not pw:
                continue
            tried += 1
            
            if tried % 500 == 0:
                console.print(f"  [dim]Tried {tried} passphrases...[/dim]", end="\r")
            
            cmd = ["steghide", "extract", "-sf", target_file, "-p", pw, "-f"]
            ok, out, err = _run(cmd, timeout=5)
            combined = out + err
            
            if ok and "wrote extracted data" in combined.lower():
                console.print(f"\n")
                console.print(Panel(
                    f"[bold green]CRACKED![/bold green]\n"
                    f"Passphrase: [bold]{pw}[/bold]\n"
                    f"Attempts: {tried:,}\n"
                    f"Output: {combined.strip()}",
                    title="🔓 Steghide Brute-Force Success!", border_style="green"))
                return
    
    console.print(f"\n[yellow]Exhausted {tried:,} passphrases. No hidden data found.[/yellow]")

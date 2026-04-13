#!/usr/bin/env python3
import os
import sys

# Automatically restart inside the virtual environment if it exists and we're not inside it
if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
    venv_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'venv')
    venv_python = os.path.join(venv_dir, 'Scripts', 'python.exe') if os.name == 'nt' else os.path.join(venv_dir, 'bin', 'python')
    
    if os.path.exists(venv_python):
        import subprocess
        sys.exit(subprocess.call([venv_python, sys.argv[0]] + sys.argv[1:]))

import cmd
import argparse
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
import pyfiglet

import core.crypto as crypto
import core.recon as recon
import core.forensics as forensics
import core.social as social
import core.github_osint as github_osint
import core.reddit_osint as reddit_osint

console = Console()

class UltintConsole(cmd.Cmd):
    intro = ""
    prompt = "\001\033[1;36m\002ultint\001\033[0m\002 > " if os.name != 'nt' else "\033[1;36multint\033[0m > "

    def preloop(self):
        from rich.console import Group
        banner_text = pyfiglet.figlet_format("ULTINT", font="slant")
        
        banner_group = Group(
            Text(banner_text, style="bold cyan"),
            Text.from_markup("[bold white]The Ultimate Intelligence Toolkit — OSINT • Forensics • Cryptanalysis[/bold white]"),
            Text.from_markup("[dim]Type 'help' or '?' to list commands.[/dim]")
        )
        
        banner = Panel(banner_group, border_style="cyan", expand=False)
        console.print(banner)

    def emptyline(self):
        """Override default cmd behavior to stop repeating last command on empty enter."""
        pass

    def do_crypto(self, arg):
        """
        Cryptography and Forensic Hash functions (CyberChef-lite)
        Usage: crypto <subcommand> <args>
        Subcommands:
            enc <method> <data>   : Encode/Encrypt (b64, b32, b85, hex, bin, oct, url, morse, atbash, rot13, caesar)
            dec <method> <data>   : Decode/Decrypt (b64, b32, b85, hex, bin, oct, url, morse, atbash, rot13, caesar)
            hash <method> <data>  : Hash generator (md5, sha1, sha256, ntlm)
            crack <hash>          : Hash Cracker (Nitrxgen API + RockYou 14.3M Auto-Downloader)
            xor <key> <data>      : XOR encryption/decryption using string or hex keys
            magic <data>          : Recursive Auto-Decoder (Bounces through 5 layers natively)
        """
        crypto.handle_command(arg, console)

    def do_recon(self, arg):
        """
        Automated Infrastructure Reconnaissance
        Usage: recon <subcommand> <target>
        Subcommands:
            scan <ip/domain>    : Full 6-phase automated recon pipeline
                                  (DNS, GeoIP, Shodan, WHOIS, Headers, Nmap)
            dns <domain>        : Deep DNS enumeration + subdomain discovery via CT logs
            headers <domain>    : HTTP header fingerprinting + security audit
            wayback <domain>    : Wayback Machine ghost endpoints + API/admin panel detection
        """
        recon.handle_command(arg, console)

    def do_forensics(self, arg):
        """
        Automated Forensic Intelligence Pipeline
        Usage: forensics <subcommand> <file>
        Subcommands:
            analyze <file>    : Full automated 7-phase investigation
                                (file ID, hashes, entropy, EXIF, steghide auto-crack,
                                 binwalk signatures, strings intelligence)
            stegcrack <file>  : Brute-force steghide passphrase using RockYou dictionary
        """
        forensics.handle_command(arg, console)

    def do_social(self, arg):
        """
        Social Media and Identity Search
        Usage: social <subcommand> <args>
        Subcommands:
            username <name> : Async Sherlock engine querying 400+ platforms
            email <address> : Silent verification of email on major platforms
        """
        social.handle_command(arg, console)

    def do_github(self, arg):
        """
        GitHub OSINT Pipeline (Keyless)
        Usage: github <username>
        Automated 5-phase scan:
            Profile intel, commit email harvesting, tech stack profiling,
            organization membership, SSH/GPG key enumeration
        """
        github_osint.handle_command(arg, console)

    def do_reddit(self, arg):
        """
        Reddit OSINT Pipeline (Keyless)
        Usage: reddit <username>
        Automated 6-phase scan:
            Profile metadata, post/comment history, subreddit activity map,
            temporal sleep cycle analysis, PII leakage scanner, writing style
        """
        reddit_osint.handle_command(arg, console)

    def do_instagram(self, arg):
        """
        Deep Instagram Analysis Sub-Shell (IG-Detective)
        Usage: instagram
        Automated OSINT: profile intel, GPS extraction, temporal analysis,
        social network graphing, stylometry, surveillance, data export
        """
        try:
            from core.ig.shell import IGDetectiveShell
            from core.ig.client import InstagramClient
        except ImportError as e:
            console.print(f"[red]Missing IG-Detective dependencies: {e}. Have you run pip install yet?[/red]")
            return

        console.print("\n[bold magenta]=====================================[/bold magenta]")
        console.print("[bold magenta]Transitioning to IG-Detective Sub-Shell[/bold magenta]")
        console.print("[dim]Type 'exit' to return to ULTINT.[/dim]")
        
        client = InstagramClient()
        shell = IGDetectiveShell(client)
        try:
            shell.cmdloop()
        except KeyboardInterrupt:
            pass
        except SystemExit:
            pass
        console.print("[bold magenta]=====================================[/bold magenta]\n")
        console.print("[bold cyan]Returned to ULTINT Framework.[/bold cyan]")

    def do_exit(self, arg):
        """Exit the ULTINT console."""
        console.print("[bold red]Exiting...[/bold red]")
        sys.exit(0)
    
    def do_quit(self, arg):
        """Exit the ULTINT console."""
        return self.do_exit(arg)

    def do_clear(self, arg):
        """Clear the screen."""
        console.clear()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="ULTINT — The Ultimate Intelligence Toolkit")
    # For now, we only launch the interactive shell
    args = parser.parse_args()
    
    try:
        UltintConsole().cmdloop()
    except KeyboardInterrupt:
        console.print("\n[bold red]Interrupted! Exiting...[/bold red]")
        sys.exit(0)

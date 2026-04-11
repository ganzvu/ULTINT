import base64
import hashlib
import binascii
import urllib.parse
import codecs
import re
import string
import os
import itertools
import requests
from rich.table import Table
from rich.panel import Panel

def is_readable(s):
    if not s or len(s) == 0:
        return False
    printable_chars = set(string.printable)
    printable_count = sum(1 for c in s if c in printable_chars and c not in '\r\n\t\x0b\x0c')
    if len(s) > 3 and printable_count / len(s) >= 0.90:
        return True
    return False

# ==========================================
# Core Decoding Logic
# ==========================================
def b64d(s):
    if re.match(r'^[A-Za-z0-9+/ \n\r]*={0,2}$', s):
        s_clean = re.sub(r'\s+', '', s)
        if len(s_clean) % 4 == 0:
            return base64.b64decode(s_clean.encode()).decode('utf-8')
    raise ValueError("Not valid Base64")

def b32d(s):
    s_clean = re.sub(r'\s+', '', s).upper()
    if re.match(r'^[A-Z2-7=]+$', s_clean) and len(s_clean) % 8 == 0:
        return base64.b32decode(s_clean.encode()).decode('utf-8')
    raise ValueError("Not valid Base32")

def hd(s):
    s_clean = re.sub(r'(0x|\\x|\s+|,|:|\n)', '', s, flags=re.IGNORECASE)
    if all(c in '0123456789abcdefABCDEF' for c in s_clean) and len(s_clean) % 2 == 0 and len(s_clean) > 0:
        return binascii.unhexlify(s_clean).decode('utf-8')
    raise ValueError("Not valid Hex")

def bind(s):
    s_clean = re.sub(r'(0b|\s+|,)', '', s, flags=re.IGNORECASE)
    if all(c in '01' for c in s_clean) and len(s_clean) % 8 == 0 and len(s_clean) > 0:
        return ''.join(chr(int(s_clean[i:i+8], 2)) for i in range(0, len(s_clean), 8))
    raise ValueError("Not valid Binary")

def octd(s):
    s_clean = re.sub(r'(\\|0o)', ' ', s, flags=re.IGNORECASE)
    parts = s_clean.split()
    if not parts:
        if len(s) % 3 == 0 and s.isdigit():
            parts = [s[i:i+3] for i in range(0, len(s), 3)]
        else: raise ValueError()
            
    if all(re.match(r'^[0-7]{2,3}$', p) for p in parts):
        return ''.join(chr(int(p, 8)) for p in parts)
    raise ValueError("Not valid Octal")

def ud(s):
    res = urllib.parse.unquote(s)
    if res != s: return res
    raise ValueError("Nothing to URL decode")

def r13(s):
    res = codecs.encode(s, 'rot_13')
    if res != s: return res
    raise ValueError("Same string")

def b85d(s):
    try: return base64.b85decode(s.encode()).decode()
    except: raise ValueError("Not valid Base85")

MORSE_DICT = {'A':'.-', 'B':'-...', 'C':'-.-.', 'D':'-..', 'E':'.', 'F':'..-.', 'G':'--.', 'H':'....', 'I':'..', 'J':'.---', 'K':'-.-', 'L':'.-..', 'M':'--', 'N':'-.', 'O':'---', 'P':'.--.', 'Q':'--.-', 'R':'.-.', 'S':'...', 'T':'-', 'U':'..-', 'V':'...-', 'W':'.--', 'X':'-..-', 'Y':'-.--', 'Z':'--..', '1':'.----', '2':'..---', '3':'...--', '4':'....-', '5':'.....', '6':'-....', '7':'--...', '8':'---..', '9':'----.', '0':'-----', ',':'--..--', '.':'.-.-.-', '?':'..--..', '/':'-..-.', '-':'-....-', '(':'-.--.', ')':'-.--.-'}
MORSE_REV = {v: k for k, v in MORSE_DICT.items()}

def morse_enc(s): return ' '.join(MORSE_DICT.get(c.upper(), c) for c in s)
def morse_dec(s): return ''.join(MORSE_REV.get(c, c) for c in s.split())

def atbash(s):
    res = ""
    for c in s:
        if c.isalpha():
            if c.isupper(): res += chr(90 - (ord(c) - 65))
            else: res += chr(122 - (ord(c) - 97))
        else: res += c
    return res

def get_transformations():
    return {
        'Base64': b64d, 'Base32': b32d, 'Base85': b85d,
        'Hex': hd, 'Binary': bind, 'Octal': octd,
        'URLDecode': ud, 'ROT13': r13
    }

def magic_decode(data, max_depth=5):
    queue = [(data, [])] 
    visited = {data}
    results = []
    transforms = get_transformations()
    
    while queue:
        current, path = queue.pop(0)
        if len(path) >= max_depth: continue
            
        for t_name, t_func in transforms.items():
            if path and path[-1] == 'ROT13' and t_name == 'ROT13': continue
            try:
                out = t_func(current)
                if out and out != current and out not in visited:
                    visited.add(out)
                    new_path = path + [t_name]
                    if is_readable(out): results.append((" -> ".join(new_path), out))
                    queue.append((out, new_path))
            except Exception: pass
                
    if not path:
        if re.match(r'^[a-fA-F0-9]{32}$', data): results.append(("Hash Magic", "Possible MD5 / NTLM"))
        elif re.match(r'^[a-fA-F0-9]{40}$', data): results.append(("Hash Magic", "Possible SHA-1"))
        elif re.match(r'^[a-fA-F0-9]{64}$', data): results.append(("Hash Magic", "Possible SHA-256"))
    return results

# ==========================================
# Crack Engine 
# ==========================================
def run_cracker(target_hash, console):
    import concurrent.futures
    target_hash = target_hash.lower()
    
    # 1. API Pass for instant lookup (MD5 only)
    if len(target_hash) == 32:
        try:
            with console.status("[cyan]Querying Nitrxgen Rainbow Tables...[/cyan]"):
                r = requests.get(f"https://www.nitrxgen.net/md5db/{target_hash}", timeout=5)
                if r.text:
                    console.print(Panel(f"Password Found (Online DB): [bold green]{r.text}[/bold green]", title="Cracker Success!", border_style="green"))
                    return
        except: pass
    
    # Auto-Download Dictionary to local data/ folder
    wordlist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    os.makedirs(wordlist_dir, exist_ok=True)
    wordlist_path = os.path.join(wordlist_dir, 'rockyou.txt')
    
    if not os.path.exists(wordlist_path):
        with console.status("[cyan]First time setup: Downloading 134MB RockYou Dictionary...[/cyan]"):
            try:
                r = requests.get("https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt", stream=True)
                with open(wordlist_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
                console.print("[green]RockYou downloaded![/green]")
            except Exception as e:
                console.print(f"[red]Failed to download wordlist: {e}[/red]")
                return

    # Determine hash length
    hash_type = "Unknown"
    if len(target_hash) == 32: hash_type = "md5_or_ntlm"
    elif len(target_hash) == 40: hash_type = "sha1"
    elif len(target_hash) == 64: hash_type = "sha256"

    if hash_type == "Unknown":
        console.print("[red]Hash length not recognized as MD5, SHA1, or SHA256.[/red]")
        return

    with console.status(f"[cyan]Attacking {hash_type} hash against 14.3 Million RockYou passwords...[/cyan]"):
        with open(wordlist_path, 'r', encoding='latin-1') as f:
            for line in f:
                word = line.rstrip('\n')
                if hash_type == "md5_or_ntlm":
                    if hashlib.md5(word.encode()).hexdigest() == target_hash:
                        console.print(Panel(f"Password Found: [bold green]{word}[/bold green]", title="Cracker Success!", border_style="green"))
                        return
                    try:
                        if hashlib.new('md4', word.encode('utf-16le')).hexdigest() == target_hash:
                            console.print(Panel(f"Password Found (NTLM): [bold green]{word}[/bold green]", title="Cracker Success!", border_style="green"))
                            return
                    except ValueError: pass
                elif hash_type == "sha1":
                    if hashlib.sha1(word.encode()).hexdigest() == target_hash:
                        console.print(Panel(f"Password Found: [bold green]{word}[/bold green]", title="Cracker Success!", border_style="green"))
                        return
                elif hash_type == "sha256":
                    if hashlib.sha256(word.encode()).hexdigest() == target_hash:
                        console.print(Panel(f"Password Found: [bold green]{word}[/bold green]", title="Cracker Success!", border_style="green"))
                        return
                        
    console.print("[yellow]Dictionary attack exhausted. Hash not found in RockYou.[/yellow]")

# ==========================================
# CLI Handler
# ==========================================
def handle_command(arg_str, console):
    args = arg_str.split()
    if not args:
        console.print("[yellow]Usage: crypto <enc|dec|hash|crack|xor|magic> <method/key> <data>[/yellow]")
        return
        
    cmd = args[0]
    
    # MAGIC MODE
    if cmd == 'magic':
        table = Table(title="Crypto: MAGIC", show_lines=True)
        table.add_column("Transformation Path", style="cyan")
        table.add_column("Result", style="green", overflow="fold")
        data = " ".join(args[1:])
        matches = magic_decode(data)
        if matches:
            seen = set()
            for path, res in sorted(matches, key=lambda x: len(x[0].split('->'))):
                if res not in seen:
                    table.add_row(path, res)
                    seen.add(res)
        else:
            table.add_row("Unknown", "No readable nested decoding discovered.")
        console.print(table)
        return

    # CRACK MODE
    if cmd == 'crack':
        if len(args) < 2:
            console.print("[red]Usage: crypto crack <hash>[/red]")
            return
        run_cracker(args[1], console)
        return
        
    # EXPLICIT MODES (enc, dec, hash)
    if cmd in ['enc', 'dec', 'hash']:
        if len(args) < 3:
            console.print(f"[red]Usage: crypto {cmd} <method> <data>[/red]")
            return
        method = args[1].lower()
        data = " ".join(args[2:])
        
        table = Table(title=f"Crypto: {cmd.upper()} {method.upper()}", show_lines=True)
        table.add_column("Input", style="cyan", overflow="fold")
        table.add_column("Output", style="green", overflow="fold")
        
        try:
            res = ""
            if cmd == 'hash':
                if method == 'md5': res = hashlib.md5(data.encode()).hexdigest()
                elif method == 'sha1': res = hashlib.sha1(data.encode()).hexdigest()
                elif method == 'sha256': res = hashlib.sha256(data.encode()).hexdigest()
                elif method == 'ntlm':
                    try: res = hashlib.new('md4', data.encode('utf-16le')).hexdigest()
                    except ValueError: res = "Error: MD4 disabled on this system's OpenSSL"
                else: raise ValueError("Unknown hash method")
                
            elif cmd == 'enc':
                if method == 'b64': res = base64.b64encode(data.encode()).decode()
                elif method == 'b32': res = base64.b32encode(data.encode()).decode()
                elif method == 'b85': res = base64.b85encode(data.encode()).decode()
                elif method == 'hex': res = binascii.hexlify(data.encode()).decode()
                elif method == 'bin': res = ' '.join(format(ord(c), '08b') for c in data)
                elif method == 'oct': res = ' '.join(format(ord(c), '03o') for c in data)
                elif method == 'url': res = urllib.parse.quote(data)
                elif method == 'morse': res = morse_enc(data)
                elif method == 'atbash': res = atbash(data)
                elif method == 'rot13': res = codecs.encode(data, 'rot_13')
                elif method == 'caesar':
                    out = ""
                    for c in data:
                        if c.isalpha():
                            b = 65 if c.isupper() else 97
                            out += chr((ord(c) - b + 3) % 26 + b)
                        else: out += c
                    res = out
                else: raise ValueError("Unknown enc method")
                
            elif cmd == 'dec':
                if method == 'b64': res = b64d(data)
                elif method == 'b32': res = b32d(data)
                elif method == 'b85': res = b85d(data)
                elif method == 'hex': res = hd(data)
                elif method == 'bin': res = bind(data)
                elif method == 'oct': res = octd(data)
                elif method == 'url': res = urllib.parse.unquote(data)
                elif method == 'morse': res = morse_dec(data)
                elif method == 'atbash': res = atbash(data)
                elif method == 'rot13': res = codecs.encode(data, 'rot_13')
                elif method == 'caesar':
                    res = "\n".join("ROT-%02d: %s" % (shift, "".join(chr((ord(c)-(65 if c.isupper() else 97)-shift)%26+(65 if c.isupper() else 97)) if c.isalpha() else c for c in data)) for shift in range(1, 26))
                else: raise ValueError("Unknown dec method")

            table.add_row(data, res)
            console.print(table)
            return
        except Exception as e:
            console.print(f"[bold red]Decoding Error[/bold red]: {e}")
            return

    # XOR MODE
    if cmd == 'xor':
        if len(args) < 3:
            console.print("[red]Usage: crypto xor <key> <data>[/red]")
            return
        key = args[1]
        data = " ".join(args[2:])
        try: data_b = binascii.unhexlify(data)
        except: data_b = data.encode()
        try: key_b = binascii.unhexlify(key)
        except: key_b = key.encode()
        out = bytes([a ^ b for a, b in zip(data_b, itertools.cycle(key_b))])
        try: res_str = out.decode('utf-8')
        except: res_str = binascii.hexlify(out).decode('utf-8')
        
        table = Table(title=f"Crypto: XOR", show_lines=True)
        table.add_column("Input", style="cyan")
        table.add_column("Output (String/Hex)", style="green")
        table.add_row(f"{data} | Key: {key}", res_str)
        console.print(table)
        return

    # To maintain backward compatibility with any previous direct parsing if necessary, 
    # but the instructions told me to overhaul logic.
    console.print(f"[red]Unknown crypto action: {cmd}[/red]")

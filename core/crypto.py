import base64
import hashlib
import binascii
import urllib.parse
import codecs
import re
import string
from rich.table import Table

def is_readable(s):
    if not s or len(s) == 0:
        return False
    printable_chars = set(string.printable)
    printable_count = sum(1 for c in s if c in printable_chars and c not in '\r\n\t\x0b\x0c')
    if len(s) > 3 and printable_count / len(s) >= 0.90:
        return True
    return False

# ==========================================
# Core Decoding Logic (Used by Magic and Manual)
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
    # Strip common hex delimiters (spaces, commas, \x, 0x, colons, newlines)
    s_clean = re.sub(r'(0x|\\x|\s+|,|:|\n)', '', s, flags=re.IGNORECASE)
    if all(c in '0123456789abcdefABCDEF' for c in s_clean) and len(s_clean) % 2 == 0 and len(s_clean) > 0:
        return binascii.unhexlify(s_clean).decode('utf-8')
    raise ValueError("Not valid Hex")

def bind(s):
    # Strip spaces, commas, 0b prefixes Let's allow chunks.
    s_clean = re.sub(r'(0b|\s+|,)', '', s, flags=re.IGNORECASE)
    if all(c in '01' for c in s_clean) and len(s_clean) % 8 == 0 and len(s_clean) > 0:
        return ''.join(chr(int(s_clean[i:i+8], 2)) for i in range(0, len(s_clean), 8))
    raise ValueError("Not valid Binary")

def octd(s):
    # Octal formats can be "154 145" or "0154 0145" or "154145" (if length is stable)
    # usually separated by spaces or backslashes `\154`
    s_clean = re.sub(r'(\\|0o)', ' ', s, flags=re.IGNORECASE)
    parts = s_clean.split()
    if not parts:
        # Try chunking by 3 if there's no spaces
        if len(s) % 3 == 0 and s.isdigit():
            parts = [s[i:i+3] for i in range(0, len(s), 3)]
        else:
            raise ValueError()
            
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

def get_transformations():
    return {
        'Base64': b64d,
        'Base32': b32d,
        'Hex': hd,
        'Binary': bind,
        'Octal': octd,
        'URLDecode': ud,
        'ROT13': r13
    }

# ==========================================

def magic_decode(data, max_depth=5):
    queue = [(data, [])] 
    visited = {data}
    results = []
    
    transforms = get_transformations()
    
    while queue:
        current, path = queue.pop(0)
        if len(path) >= max_depth:
            continue
            
        for t_name, t_func in transforms.items():
            if path and path[-1] == 'ROT13' and t_name == 'ROT13':
                continue
                
            try:
                out = t_func(current)
                if out and out != current and out not in visited:
                    visited.add(out)
                    new_path = path + [t_name]
                    
                    if is_readable(out):
                        results.append((" -> ".join(new_path), out))
                    
                    queue.append((out, new_path))
            except Exception:
                pass
                
    if not path:
        if re.match(r'^[a-fA-F0-9]{32}$', data): results.append(("Hash Magic", "Possible MD5 / NTLM"))
        elif re.match(r'^[a-fA-F0-9]{40}$', data): results.append(("Hash Magic", "Possible SHA-1"))
        elif re.match(r'^[a-fA-F0-9]{64}$', data): results.append(("Hash Magic", "Possible SHA-256"))
        
    return results

def handle_command(arg_str, console):
    args = arg_str.split()
    valid_cmds = ['b64e', 'b64d', 'b32e', 'b32d', 'md5', 'sha256', 'hex', 'unhex', 'url', 'rot13', 'bin', 'unbin', 'oct', 'unoct', 'magic', 'auto']
    
    if not args:
        console.print(f"[yellow]Please provide a subcommand: auto, b64d, unhex, unbin, etc...[/yellow]")
        return
    
    if len(args) == 1 and args[0] not in valid_cmds:
        subcmd = 'magic'
        data = args[0]
    else:
        subcmd = args[0]
        data = arg_str[len(subcmd):].strip() # Use raw remainder of string instead of strict split to preserve spacing!
    
    if not data:
        console.print("[red]Please provide data to process.[/red]")
        return

    table = Table(title=f"Crypto: {subcmd.upper()}", show_lines=True)
    
    if subcmd in ['auto', 'magic']:
        table.add_column("Transformation Path", style="cyan")
        table.add_column("Result", style="green", overflow="fold")
        
        matches = magic_decode(data)
        if matches:
            seen_results = set()
            for path, res in sorted(matches, key=lambda x: len(x[0].split('->'))):
                if res not in seen_results:
                    table.add_row(path, res)
                    seen_results.add(res)
        else:
            table.add_row("Unknown", "No readable nested decoding discovered.")
            
        console.print(table)
        return

    table.add_column("Input", style="cyan", overflow="fold")
    table.add_column("Output", style="green", overflow="fold")

    try:
        # Encodings
        if subcmd == 'b64e': res = base64.b64encode(data.encode()).decode(); table.add_row(data, res)
        elif subcmd == 'b32e': res = base64.b32encode(data.encode()).decode(); table.add_row(data, res)
        elif subcmd == 'hex': res = binascii.hexlify(data.encode()).decode(); table.add_row(data, res)
        elif subcmd == 'bin': res = ' '.join(format(ord(c), '08b') for c in data); table.add_row(data, res)
        elif subcmd == 'oct': res = ' '.join(format(ord(c), '03o') for c in data); table.add_row(data, res)
        # Unified Decodings from Core Logic
        elif subcmd == 'b64d': table.add_row(data, b64d(data))
        elif subcmd == 'b32d': table.add_row(data, b32d(data))
        elif subcmd == 'unhex': table.add_row(data, hd(data))
        elif subcmd == 'unbin': table.add_row(data, bind(data))
        elif subcmd == 'unoct': table.add_row(data, octd(data))
        # Misc
        elif subcmd == 'url': table.add_row(data, urllib.parse.unquote(data))
        elif subcmd == 'rot13': table.add_row(data, codecs.encode(data, 'rot_13'))
        elif subcmd == 'md5': table.add_row(data, hashlib.md5(data.encode()).hexdigest())
        elif subcmd == 'sha256': table.add_row(data, hashlib.sha256(data.encode()).hexdigest())
        else:
            console.print(f"[red]Unknown crypto subcommand: {subcmd}[/red]")
            return
            
        console.print(table)
    except Exception as e:
        console.print(f"[bold red]Decoding Error[/bold red]: {e}")

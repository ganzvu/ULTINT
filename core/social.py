import asyncio
import httpx
import json
import os
import re
from rich.table import Table
from rich.live import Live
from rich.panel import Panel

# Use fake user agent to prevent basic blocks
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}

async def check_site(client, site_name, site_info, target):
    base_url = site_info.get("url", "").replace("{}", target)
    probe_url = site_info.get("urlProbe", base_url).replace("{}", target)
    if not base_url: return None
    
    error_type = site_info.get("errorType")
    error_msgs = site_info.get("errorMsg", [])
    if isinstance(error_msgs, str):
        error_msgs = [error_msgs] # standardize to list
        
    method = site_info.get("request_method", "GET").upper()
    # Format payload dict
    payload_str = json.dumps(site_info.get("request_payload", {})).replace('"{}"', f'"{target}"')
    payload = json.loads(payload_str) if payload_str != "{}" else None
    
    headers = dict(HEADERS)
    if "headers" in site_info:
        for k, v in site_info["headers"].items():
            headers[k] = v.replace("{}", target)
            
    try:
        # Sherlock strictly prohibits redirects unless the schema relies on reading the response_url
        should_redirect = (error_type == "response_url")
        
        if method == "POST":
            response = await client.post(probe_url, headers=headers, json=payload, timeout=10, follow_redirects=should_redirect)
        else:
            response = await client.get(probe_url, headers=headers, timeout=10, follow_redirects=should_redirect)
            
        status_code = response.status_code
        text = response.text
        
        found = False
        target_resp_url = str(response.url)
        
        # Check if the site aggressively redirected us to a homepage or search page
        import urllib.parse
        orig_parsed = urllib.parse.urlparse(probe_url)
        final_parsed = urllib.parse.urlparse(target_resp_url)
        path_diverged = (orig_parsed.path.rstrip('/') != final_parsed.path.rstrip('/'))
        
        # Advanced Heuristic to catch websites that lie about status codes (Soft-404s) or throw Cloudflare captchas 
        def is_soft_404(html):
            h = html.lower()
            bad_phrases = [
                "page not found", "404 not found", "error 404", "could not be found",
                "doesn't exist", "does not exist", "no page found", "404 error",
                "cloudflare", "attention required!", "captcha", "security check",
                "não existe", "não encontrada", "página não", "perfil não",
                "no existe", "página no", "perfil no", 
                "n'existe pas", "introuvable",
                "verify you are human", "enable javascript"
            ]
            return any(phrase in h for phrase in bad_phrases)

        if error_type == "status_code":
            if status_code == 200 and not path_diverged: 
                if not is_soft_404(text): found = True
        elif error_type == "message":
            if status_code == 200 and not path_diverged:
                if not any(msg in text for msg in error_msgs):
                    if not is_soft_404(text): found = True
        elif error_type == "response_url":
            error_url = site_info.get("errorUrl", "").replace("{}", target)
            
            if status_code >= 200 and status_code < 300:
                if error_url and target_resp_url.startswith(error_url):
                    found = False
                elif not path_diverged:
                    if not is_soft_404(text): found = True
        else:
            if status_code == 200 and not path_diverged: 
                if not is_soft_404(text): found = True
            
        if found:
            return (site_name, base_url, "[green]Found![/green]")
            
    except Exception:
        pass
        
    return None

async def run_sherlock(target, console):
    json_path = os.path.join(os.path.dirname(__file__), 'sherlock_data.json')
    if not os.path.exists(json_path):
        console.print("[red]Sherlock core/sherlock_data.json missing! Please run the install script or wget it.[/red]")
        return
        
    with open(json_path, 'r', encoding='utf-8') as f:
        site_data = json.load(f)
        
    table = Table(title=f"Sherlock Asynchronous Trace: {target}", show_lines=True)
    table.add_column("Platform", style="cyan")
    table.add_column("URL", overflow="fold")
    table.add_column("Status", style="bold")
    
    found_count = 0
    total = len([s for s in site_data.keys() if s != "$schema"])

    console.print(f"[dim]Initiating async resolution for [bold]{total}[/bold] platforms...[/dim]")
    
    with Live(table, console=console, refresh_per_second=4):
        # We will dispatch queries with httpx.AsyncClient
        # Limit concurrency to 50 so we don't blow up our own sockets
        limits = httpx.Limits(max_connections=50, max_keepalive_connections=10)
        async with httpx.AsyncClient(limits=limits) as client:
            tasks = []
            for site_name, site_info in site_data.items():
                if site_name == "$schema": continue
                tasks.append(check_site(client, site_name, site_info, target))
                
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    site_name, url, status = result
                    table.add_row(site_name, url, status)
                    found_count += 1
                    table.title = f"Sherlock Output: {target} (Found: {found_count})"

async def run_holehe(email, console):
    # Holehe logic usually pings endpoints where users submit "forgot password" or "signup"
    # To avoid account lockouts, we just check known safe OSINT verification endpoints.
    # We will expand this as needed, but here's the framework:
    
    console.print(f"[cyan]Initiating Silent Email Trap for {email}...[/cyan]")
    table = Table(show_lines=True)
    table.add_column("Provider", style="cyan")
    table.add_column("Email Status", style="green")
    
    # Gravatar JSON API 
    # If they have a gravatar, they definitely exist
    import hashlib
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    
    async with httpx.AsyncClient() as client:
        # Check 1: Gravatar Profile
        try:
            r = await client.get(f"https://en.gravatar.com/{email_hash}.json", headers=HEADERS)
            if r.status_code == 200:
                table.add_row("Gravatar", "[bold green]Registered (Profile Exists)[/bold green]")
            else:
                table.add_row("Gravatar", "[dim]Not found[/dim]")
        except: pass
        
        # Check 2: HaveIBeenPwned API (Free partial endpoint for breach check if possible, or skip)
        try:
            r = await client.get(f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}", headers={"User-Agent": "ULTINT/1.0", "hibp-api-key": ""}) 
            # Needs key in real HIBP, but if it 401s we know we hit it. Here we simulate the logic.
            # We'll skip HIBP if no key to prevent console spam
            pass
        except: pass
        
        # Check 3: Spotify (Often tells you if email is in use during signup validation)
        try:
            r = await client.get(f"https://spclient.wg.spotify.com/signup/public/v1/account?validate=1&email={email}", headers=HEADERS)
            if r.status_code == 200:
                data = r.json()
                if data.get("status") == 20: 
                    table.add_row("Spotify", "[bold green]Registered[/bold green]")
                else:
                    table.add_row("Spotify", "[dim]Not found[/dim]")
        except: pass
        
        # Check 4: Imgur Password Reset (Does not alert user in API validation phase)
        try:
            r = await client.post("https://imgur.com/signin/ajax_email_available", data={"email": email}, headers=HEADERS)
            if r.status_code == 200:
                data = r.json()
                if data.get("data", {}).get("available") is False:
                    table.add_row("Imgur", "[bold green]Registered[/bold green]")
                else:
                    table.add_row("Imgur", "[dim]Not found[/dim]")
        except: pass

    console.print(table)


def handle_command(arg_str, console):
    args = arg_str.split()
    if not args:
        console.print("[yellow]Usage: social username <name> OR social email <email>[/yellow]")
        return
    
    subcmd = args[0]
    target = " ".join(args[1:])
    
    if not target:
        console.print("[red]Please provide a target string.[/red]")
        return
        
    if subcmd == 'username':
        # Execute the AsyncSherlock Engine
        try:
            asyncio.run(run_sherlock(target, console))
        except KeyboardInterrupt:
            console.print("\n[red]Scan aborted by user.[/red]")
            
    elif subcmd == 'email':
        try:
            asyncio.run(run_holehe(target, console))
        except KeyboardInterrupt:
            console.print("\n[red]Scan aborted by user.[/red]")
            
    else:
        console.print(f"[red]Unknown social subcommand: {subcmd}[/red]")

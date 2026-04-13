import requests
import re
from rich.table import Table
from rich.panel import Panel


GITHUB_API = "https://api.github.com"
HEADERS = {"User-Agent": "ULTINT/1.0", "Accept": "application/vnd.github.v3+json"}


def handle_command(username, console):
    """Full automated GitHub OSINT pipeline. Zero API keys required."""
    username = username.strip().lstrip('@')
    if not username:
        console.print("[red]Usage: github <username>[/red]")
        return
    
    findings = []
    console.print(Panel(f"[bold]Target: {username}[/bold]", title="🐙 GitHub OSINT Pipeline", border_style="cyan"))

    # ── Phase 1: Profile Intelligence ───────────────
    with console.status("[cyan]Phase 1: Fetching profile metadata...[/cyan]"):
        try:
            r = requests.get(f"{GITHUB_API}/users/{username}", headers=HEADERS, timeout=10)
            if r.status_code == 404:
                console.print(f"[red]GitHub user '{username}' not found.[/red]")
                return
            if r.status_code == 403:
                console.print("[yellow]GitHub API rate limit reached (60/hr unauthenticated). Try again later.[/yellow]")
                return
            if r.status_code != 200:
                console.print(f"[red]GitHub API error: HTTP {r.status_code}[/red]")
                return
            profile = r.json()
        except Exception as e:
            console.print(f"[red]Failed to reach GitHub API: {e}[/red]")
            return

    table = Table(title="Phase 1: Profile Intelligence", show_lines=True)
    table.add_column("Field", style="cyan", min_width=15)
    table.add_column("Value", style="green", overflow="fold")

    table.add_row("Username", profile.get('login', ''))
    table.add_row("User ID", str(profile.get('id', '')))
    
    if profile.get('name'):
        table.add_row("Real Name", f"[bold yellow]{profile['name']}[/bold yellow]")
        findings.append(f"👤 Real name: {profile['name']}")
    if profile.get('bio'):
        table.add_row("Bio", profile['bio'])
    if profile.get('company'):
        table.add_row("Company", f"[bold yellow]{profile['company']}[/bold yellow]")
        findings.append(f"🏢 Company: {profile['company']}")
    if profile.get('location'):
        table.add_row("Location", f"[bold yellow]{profile['location']}[/bold yellow]")
        findings.append(f"📍 Location: {profile['location']}")
    if profile.get('email'):
        table.add_row("Public Email", f"[bold yellow]{profile['email']}[/bold yellow]")
        findings.append(f"📧 Public email: {profile['email']}")
    if profile.get('blog'):
        table.add_row("Website/Blog", f"[bold yellow]{profile['blog']}[/bold yellow]")
        findings.append(f"🌐 Website: {profile['blog']}")
    if profile.get('twitter_username'):
        table.add_row("Twitter/X", f"[bold yellow]@{profile['twitter_username']}[/bold yellow]")
        findings.append(f"𝕏 Twitter: @{profile['twitter_username']}")
    
    table.add_row("Public Repos", str(profile.get('public_repos', 0)))
    table.add_row("Public Gists", str(profile.get('public_gists', 0)))
    table.add_row("Followers", str(profile.get('followers', 0)))
    table.add_row("Following", str(profile.get('following', 0)))
    table.add_row("Account Created", profile.get('created_at', '')[:10])

    console.print(table)

    # ── Phase 2: Commit Email Harvesting ────────────
    # The #1 GitHub dox: people expose personal emails in git commit metadata
    with console.status("[cyan]Phase 2: Harvesting commit emails from public repos...[/cyan]"):
        harvested_emails = set()
        try:
            # Get user's repos
            r = requests.get(f"{GITHUB_API}/users/{username}/repos?per_page=10&sort=updated",
                           headers=HEADERS, timeout=10)
            if r.status_code == 200:
                repos = r.json()
                for repo in repos[:10]:
                    repo_name = repo.get('full_name', '')
                    if repo.get('fork'):
                        continue  # Skip forks
                    try:
                        cr = requests.get(
                            f"{GITHUB_API}/repos/{repo_name}/commits?per_page=5&author={username}",
                            headers=HEADERS, timeout=10
                        )
                        if cr.status_code == 200:
                            commits = cr.json()
                            for commit in commits:
                                commit_data = commit.get('commit', {})
                                author = commit_data.get('author', {})
                                email = author.get('email', '')
                                if email and 'noreply' not in email and email not in harvested_emails:
                                    harvested_emails.add(email)
                    except Exception:
                        pass
        except Exception:
            pass

        if harvested_emails:
            findings.append(f"📧 {len(harvested_emails)} email(s) harvested from git commits")
            email_text = '\n'.join(f"  [bold yellow]{e}[/bold yellow]" for e in harvested_emails)
            console.print(Panel(email_text, title=f"🔓 Phase 2: Commit Emails ({len(harvested_emails)} found)", border_style="green"))
        else:
            console.print("[dim]Phase 2: No exposed emails in recent commits (user may use noreply).[/dim]")

    # ── Phase 3: Tech Stack Profiling ───────────────
    with console.status("[cyan]Phase 3: Profiling technology stack...[/cyan]"):
        try:
            r = requests.get(f"{GITHUB_API}/users/{username}/repos?per_page=100&sort=updated",
                           headers=HEADERS, timeout=10)
            if r.status_code == 200:
                repos = r.json()
                lang_stats = {}
                repo_topics = []
                
                for repo in repos:
                    lang = repo.get('language')
                    if lang:
                        lang_stats[lang] = lang_stats.get(lang, 0) + 1
                    repo_topics.extend(repo.get('topics', []))
                
                if lang_stats:
                    sorted_langs = sorted(lang_stats.items(), key=lambda x: x[1], reverse=True)
                    table = Table(title="Phase 3: Technology Stack", show_lines=True)
                    table.add_column("Language", style="cyan")
                    table.add_column("Repos", style="green")
                    table.add_column("Bar", style="yellow")
                    
                    max_count = sorted_langs[0][1] if sorted_langs else 1
                    for lang, count in sorted_langs[:10]:
                        bar = "█" * int((count / max_count) * 20)
                        table.add_row(lang, str(count), bar)
                    console.print(table)
                    
                    top_lang = sorted_langs[0][0]
                    findings.append(f"💻 Primary language: {top_lang} ({sorted_langs[0][1]} repos)")
                
                if repo_topics:
                    from collections import Counter
                    top_topics = Counter(repo_topics).most_common(10)
                    topics_str = ", ".join(f"{t[0]} ({t[1]})" for t in top_topics)
                    console.print(f"  [dim]Topics: {topics_str}[/dim]")
        except Exception:
            pass

    # ── Phase 4: Organization Membership ────────────
    with console.status("[cyan]Phase 4: Checking organization membership...[/cyan]"):
        try:
            r = requests.get(f"{GITHUB_API}/users/{username}/orgs", headers=HEADERS, timeout=10)
            if r.status_code == 200:
                orgs = r.json()
                if orgs:
                    org_names = [o.get('login', '') for o in orgs]
                    findings.append(f"🏛️ Organizations: {', '.join(org_names)}")
                    console.print(f"  [cyan]Organizations:[/cyan] {', '.join(org_names)}")
                else:
                    console.print("[dim]Phase 4: No public organization memberships.[/dim]")
        except Exception:
            pass

    # ── Phase 5: Recent Activity & SSH Keys ─────────
    with console.status("[cyan]Phase 5: Checking SSH keys and recent events...[/cyan]"):
        try:
            # SSH keys (public endpoint!)
            r = requests.get(f"{GITHUB_API}/users/{username}/keys", headers=HEADERS, timeout=10)
            if r.status_code == 200:
                keys = r.json()
                if keys:
                    findings.append(f"🔑 {len(keys)} public SSH key(s) exposed")
                    for key in keys[:3]:
                        key_preview = key.get('key', '')[:60] + "..."
                        console.print(f"  [dim]SSH Key #{key['id']}: {key_preview}[/dim]")
        except Exception:
            pass

        try:
            # GPG keys
            r = requests.get(f"{GITHUB_API}/users/{username}/gpg_keys", headers=HEADERS, timeout=10)
            if r.status_code == 200:
                gpg_keys = r.json()
                if gpg_keys:
                    for gk in gpg_keys:
                        for email_obj in gk.get('emails', []):
                            email = email_obj.get('email', '')
                            if email and 'noreply' not in email:
                                findings.append(f"📧 GPG key email: {email}")
                                console.print(f"  [bold yellow]GPG Email: {email}[/bold yellow]")
        except Exception:
            pass

    # ── FINAL REPORT ────────────────────────────────
    console.print()
    if findings:
        report = '\n'.join(f"  {f}" for f in findings)
        console.print(Panel(report, title="📋 GITHUB INTELLIGENCE SUMMARY", border_style="bold green"))
    else:
        console.print(Panel("[dim]Scan complete. No significant PII exposed.[/dim]", title="📋 Scan Complete", border_style="dim"))

import requests
import re
from datetime import datetime, timezone
from collections import Counter
from rich.table import Table
from rich.panel import Panel


HEADERS = {"User-Agent": "ULTINT/1.0 (OSINT Research Tool)"}


def handle_command(username, console):
    """Full automated Reddit OSINT pipeline. Zero API keys required."""
    username = username.strip().lstrip('u/').lstrip('@')
    if not username:
        console.print("[red]Usage: reddit <username>[/red]")
        return
    
    findings = []
    console.print(Panel(f"[bold]Target: u/{username}[/bold]", title="🔴 Reddit OSINT Pipeline", border_style="cyan"))

    # ── Phase 1: Profile Metadata ───────────────────
    with console.status("[cyan]Phase 1: Fetching profile metadata...[/cyan]"):
        try:
            r = requests.get(f"https://www.reddit.com/user/{username}/about.json",
                           headers=HEADERS, timeout=10)
            if r.status_code == 404:
                console.print(f"[red]Reddit user 'u/{username}' not found.[/red]")
                return
            if r.status_code == 429:
                console.print("[yellow]Reddit rate limited. Try again in a minute.[/yellow]")
                return
            if r.status_code != 200:
                console.print(f"[red]Reddit API error: HTTP {r.status_code}[/red]")
                return
            profile = r.json().get('data', {})
        except Exception as e:
            console.print(f"[red]Failed to reach Reddit: {e}[/red]")
            return

    created = datetime.fromtimestamp(profile.get('created_utc', 0), tz=timezone.utc)
    account_age_days = (datetime.now(timezone.utc) - created).days

    table = Table(title="Phase 1: Profile Intelligence", show_lines=True)
    table.add_column("Field", style="cyan", min_width=15)
    table.add_column("Value", style="green", overflow="fold")

    table.add_row("Username", f"u/{profile.get('name', username)}")
    table.add_row("Account Created", created.strftime("%Y-%m-%d"))
    table.add_row("Account Age", f"{account_age_days} days ({account_age_days // 365} years)")
    table.add_row("Post Karma", f"{profile.get('link_karma', 0):,}")
    table.add_row("Comment Karma", f"{profile.get('comment_karma', 0):,}")
    table.add_row("Total Karma", f"{profile.get('total_karma', 0):,}")
    
    if profile.get('is_gold'):
        table.add_row("Reddit Premium", "[bold yellow]Yes (Gold)[/bold yellow]")
    if profile.get('is_mod'):
        table.add_row("Moderator", "[bold red]Yes[/bold red]")
        findings.append("🛡️ User is a subreddit moderator")
    if profile.get('verified'):
        table.add_row("Verified Email", "[green]Yes[/green]")
    
    console.print(table)

    # ── Phase 2: Post History Analysis ──────────────
    all_posts = []
    all_comments = []
    
    with console.status("[cyan]Phase 2: Scraping post and comment history...[/cyan]"):
        # Fetch posts
        try:
            r = requests.get(f"https://www.reddit.com/user/{username}/submitted.json?limit=100&sort=new",
                           headers=HEADERS, timeout=15)
            if r.status_code == 200:
                all_posts = r.json().get('data', {}).get('children', [])
        except Exception:
            pass

        # Fetch comments
        try:
            r = requests.get(f"https://www.reddit.com/user/{username}/comments.json?limit=100&sort=new",
                           headers=HEADERS, timeout=15)
            if r.status_code == 200:
                all_comments = r.json().get('data', {}).get('children', [])
        except Exception:
            pass

    total_activity = len(all_posts) + len(all_comments)
    console.print(f"  [dim]Retrieved {len(all_posts)} posts and {len(all_comments)} comments.[/dim]")

    if total_activity == 0:
        console.print("[yellow]No public activity found. Account may be shadowbanned or empty.[/yellow]")
        return

    # ── Phase 3: Subreddit Activity Map ─────────────
    with console.status("[cyan]Phase 3: Mapping subreddit activity...[/cyan]"):
        subreddit_counts = Counter()
        for post in all_posts:
            sub = post.get('data', {}).get('subreddit', '')
            if sub:
                subreddit_counts[sub] += 1
        for comment in all_comments:
            sub = comment.get('data', {}).get('subreddit', '')
            if sub:
                subreddit_counts[sub] += 1

        if subreddit_counts:
            table = Table(title="Phase 3: Subreddit Activity Map", show_lines=True)
            table.add_column("Subreddit", style="cyan")
            table.add_column("Activity", style="green")
            table.add_column("Category", style="yellow")
            
            # Categorize subreddits by topic hints
            location_subs = []
            for sub, count in subreddit_counts.most_common(15):
                category = _categorize_subreddit(sub)
                table.add_row(f"r/{sub}", str(count), category)
                if category in ["Location/City", "Local"]:
                    location_subs.append(sub)
            
            console.print(table)
            
            findings.append(f"📊 Active in {len(subreddit_counts)} subreddits")
            if location_subs:
                findings.append(f"📍 Location-related subs: {', '.join(location_subs)}")

    # ── Phase 4: Temporal Analysis ──────────────────
    with console.status("[cyan]Phase 4: Temporal behavior analysis...[/cyan]"):
        timestamps = []
        for item in all_posts + all_comments:
            ts = item.get('data', {}).get('created_utc', 0)
            if ts:
                timestamps.append(datetime.fromtimestamp(ts, tz=timezone.utc))

        if timestamps:
            hour_counts = Counter(t.hour for t in timestamps)
            day_counts = Counter(t.strftime('%A') for t in timestamps)
            
            # Find sleep gap (consecutive hours with zero or minimal activity)
            hourly = [hour_counts.get(h, 0) for h in range(24)]
            max_gap, sleep_start, current_gap, current_start = 0, 0, 0, 0
            double = hourly + hourly
            for i, count in enumerate(double):
                if count == 0:
                    current_gap += 1
                else:
                    if current_gap > max_gap:
                        max_gap = current_gap
                        sleep_start = current_start % 24
                    current_gap = 0
                    current_start = i + 1
            
            # Activity heatmap (simple text version)
            max_h = max(hourly) if hourly else 1
            heatmap_lines = []
            for h in range(24):
                bar_len = int((hourly[h] / max_h) * 20) if max_h > 0 else 0
                bar = "█" * bar_len
                heatmap_lines.append(f"  [cyan]{h:02d}:00[/cyan] {bar} ({hourly[h]})")
            
            console.print(Panel('\n'.join(heatmap_lines), title="Phase 4: Activity Heatmap (UTC)", border_style="magenta"))
            
            if max_gap >= 4:
                findings.append(f"😴 Sleep gap: {sleep_start}:00-{(sleep_start + max_gap) % 24}:00 UTC ({max_gap}h)")
            
            # Most active day
            if day_counts:
                top_day = day_counts.most_common(1)[0]
                findings.append(f"📅 Most active day: {top_day[0]} ({top_day[1]} posts)")

    # ── Phase 5: PII Leakage Scan ───────────────────
    with console.status("[cyan]Phase 5: Scanning for PII leakage...[/cyan]"):
        all_text = []
        for item in all_posts + all_comments:
            data = item.get('data', {})
            text = data.get('selftext', '') or data.get('body', '') or ''
            title = data.get('title', '') or ''
            all_text.append(text + ' ' + title)
        
        full_text = ' '.join(all_text)
        
        pii = {
            'emails': list(set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', full_text)))[:5],
            'phones': list(set(re.findall(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', full_text)))[:5],
            'urls': list(set(re.findall(r'https?://[^\s)\]>]+', full_text)))[:10],
            'ages': list(set(re.findall(r'\b(?:I am|I\'m|im)\s+(\d{1,2})\s*(?:years?\s*old|yo|M|F|m|f)\b', full_text, re.IGNORECASE)))[:3],
            'locations': list(set(re.findall(r'\b(?:I live in|I\'m from|I\'m in|based in|located in)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)', full_text)))[:5],
        }
        
        pii_found = False
        for category, items in pii.items():
            if items:
                pii_found = True
                findings.append(f"🔍 PII ({category}): {', '.join(str(i) for i in items[:3])}")
                for item in items:
                    console.print(f"  [bold yellow]{category.upper()}:[/bold yellow] {item}")
        
        if not pii_found:
            console.print("[dim]Phase 5: No obvious PII leakage detected.[/dim]")

    # ── Phase 6: Writing Style (Mini-Stylometry) ────
    with console.status("[cyan]Phase 6: Analyzing writing style...[/cyan]"):
        comment_texts = [c.get('data', {}).get('body', '') for c in all_comments if c.get('data', {}).get('body')]
        
        if len(comment_texts) >= 5:
            all_words = ' '.join(comment_texts).lower().split()
            
            if all_words:
                # Avg word count per comment
                avg_len = sum(len(t.split()) for t in comment_texts) / len(comment_texts)
                
                # Unique word ratio (lexical diversity)
                unique = len(set(all_words))
                diversity = unique / len(all_words) if all_words else 0
                
                table = Table(title="Phase 6: Writing Profile", show_lines=True)
                table.add_column("Metric", style="cyan")
                table.add_column("Value", style="green")
                table.add_row("Avg Comment Length", f"{avg_len:.1f} words")
                table.add_row("Lexical Diversity", f"{diversity:.3f}")
                table.add_row("Total Words Analyzed", f"{len(all_words):,}")
                console.print(table)
        else:
            console.print("[dim]Phase 6: Not enough comments for stylometry.[/dim]")

    # ── FINAL REPORT ────────────────────────────────
    console.print()
    if findings:
        report = '\n'.join(f"  {f}" for f in findings)
        console.print(Panel(report, title="📋 REDDIT INTELLIGENCE SUMMARY", border_style="bold green"))
    else:
        console.print(Panel("[dim]Scan complete. No significant findings.[/dim]", title="📋 Scan Complete", border_style="dim"))


def _categorize_subreddit(name):
    """Attempt to categorize a subreddit name by topic."""
    n = name.lower()
    
    # City/Location subreddits (very common pattern)
    city_patterns = ['city', 'town', 'state', 'country', 'nyc', 'la', 'sf', 'chicago',
                    'seattle', 'portland', 'denver', 'austin', 'boston', 'dallas',
                    'houston', 'atlanta', 'miami', 'london', 'toronto', 'vancouver']
    if any(p in n for p in city_patterns):
        return "Location/City"
    
    tech_patterns = ['programming', 'python', 'javascript', 'java', 'linux', 'coding',
                    'webdev', 'gamedev', 'datascience', 'machinelearning', 'cyber',
                    'hacking', 'netsec', 'security', 'sysadmin', 'devops']
    if any(p in n for p in tech_patterns):
        return "Technology"
    
    gaming_patterns = ['gaming', 'games', 'xbox', 'playstation', 'nintendo', 'pcgaming',
                      'minecraft', 'fortnite', 'valorant', 'leagueoflegends']
    if any(p in n for p in gaming_patterns):
        return "Gaming"
    
    return ""

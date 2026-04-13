# 🕵️‍♂️💻 ULTINT: The OSINT & Forensics Framework

<div align="center">
  <p><strong>The Premium Local Intelligence Platform for NCL, TraceLabs, and Applied Cryptography.</strong></p>
  <p><i>Command-Line Interface built with ❤️ using Python & Rich.</i></p>
</div>

---

## 📖 Overview

ULTINT isn't just an OSINT scraper—it is a heavy-duty, unified interaction shell designed for high-stakes Capture The Flag (CTF) environments and competitive intelligence gathering. 

Instead of juggling 15 different browser tabs and dirty terminal scripts, ULTINT pulls everything into one blazing-fast, aesthetically beautiful wrapper. It effortlessly integrates classic network reconnaissance with experimental machine-learning deep analysis tools like the embedded **IG-Detective** sub-shell.

---

## ⚡ The Arsenal

### 🔐 1. Cryptography Toolkit (`crypto`)
A fully-fledged `CyberChef-Lite` built directly into your terminal. Designed specifically to tear down standard CTF cryptography roadblocks.

* **Encoders/Decoders**: `base64`, `base32`, `base85`, `hex`, `binary`, `octal`, `url`.
* **Ciphers**: Supports rolling `xor`, `morse`, `atbash`, and automatically brute-forces all 25 variants of the `caesar` cypher simultaneously.
* **Auto-Magic Decoder (`crypto magic <data>`)**: Employs a Breadth-First Search (BFS) algorithm to dynamically rip through multi-layered encodings (up to 5 layers deep) until human-readable text breaks free.
* **Hash Cracking (`crypto crack <hash>`)**: Instant DB lookups and local dictionary attacks! Automatically downloads the full **14.3 Million RockYou Dictionary**, streaming it sequentially to crack MD5, SHA-1, SHA-256, and NTLM targets using zero RAM footprint.

### 🌎 2. Social & Identity Hunt (`social`)
High-performance OSINT hunting engines.
* **AsyncSherlock (`username`)**: Probes 400+ targeted social footprint platforms concurrently using a custom `httpx` async engine. Features aggressive heuristic and redirect filtration to defeat Soft-404 false positives on adult platforms and JS applications.
* **Silent Email Traps (`email`)**: Conducts unauthenticated backend-API checks against systems like Spotify, Imgur, and Gravatar to verify if an email exists *without* alerting the target.

### 🔭 3. Active & Passive Recon (`recon`)
Infrastructure mapping tools designed to stay completely stealthy.
* **Full Automated Scan (`scan`)**: One command triggers a 6-phase pipeline — DNS resolution, GeoIP intelligence, Shodan InternetDB (keyless CVE/port lookup), WHOIS/RDAP, HTTP header fingerprinting, and a fast `nmap` sweep.
* **Deep DNS Enumeration (`dns`)**: Queries all standard record types (A, AAAA, MX, NS, TXT, SOA, CNAME) and harvests subdomains from Certificate Transparency logs.
* **HTTP Header Audit (`headers`)**: Fingerprints server technology and checks for missing security headers (CSP, HSTS, X-Frame-Options, etc.).
* **Wayback CDX (`wayback`)**: Rips historical URLs and ghost-endpoints from Archive.org.

### 🔬 4. Local Forensics (`forensics`)
* **Full Automated Analysis (`analyze`)**: A 7-phase forensic pipeline — file type/magic-byte identification, multi-hash computation (MD5/SHA-1/SHA-256), Shannon entropy analysis, EXIF metadata extraction, steghide auto-crack with common passphrases, binwalk embedded-file detection, and strings intelligence (flags, URLs, credentials).
* **Steghide Brute-Force (`stegcrack`)**: Runs a full dictionary attack against a steghide-embedded file using the RockYou wordlist when quick auto-crack fails.

### 🕵️ 5. IG-Detective Sub-Shell (`instagram`)
Need to dig deeper? Seamlessly switch from standard OSINT into our heavy-duty Data Science framework perfectly designed for live Instagram profile investigation:
* **Profile Recon (`info`)**: Scrapes public profile metadata, hidden business emails, and external IDs.
* **Timeline Analysis (`posts`)**: Fetches recent posts and computes aggregate engagement statistics.
* **Location Extraction (`addrs`)**: Pulls GPS coordinates from post metadata and reverse-geocodes them to addresses.
* **Data Export (`data`)**: Archives posts, followers, following, and stories into a local ZIP file.
* **Active Surveillance (`surveillance`)**: Continuously monitors a profile for follower/following diffs, media uploads, and bio changes using Poisson-jittered polling to evade detection.
* **Stylometry (`stylometry`)**: Natural Language Processing (NLTK) linguistics to profile a user's language patterns via n-grams, emoji usage, and punctuation habits.
* **Social Network Analysis (`sna`)**: Identifies the target's "Inner Circle" via NetworkX graph charting of tagged interactions.
* **Temporal Intelligence (`temporal`)**: Machine Learning (DBSCAN) spatial anomaly detection to unearth the target's precise timezone and biological sleep schedule.

---

## 🚀 Installation & Setup

### ⚡ Quick Install (Linux/macOS)
```bash
git clone https://github.com/ganzvu/ULTINT.git
cd ULTINT
chmod +x install.sh && ./install.sh
```

### Manual Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/ganzvu/ULTINT.git
   cd ULTINT
   ```

2. **Initialize the Virtual Environment**
   ULTINT heavily utilizes a virtual environment (`venv`) to keep complex data science dependencies isolated from your system packages.
   
   *Linux/macOS:*
   ```bash
   python3 -m venv venv
   ```
   *Windows (PowerShell):*
   ```powershell
   python.exe -m venv venv
   ```

3. **Install Dependencies & Playwright**
   
   *Linux/macOS:*
   ```bash
   ./venv/bin/pip install -r requirements.txt
   ./venv/bin/python3 -m playwright install chromium
   ```
   *Windows (PowerShell):*
   ```powershell
   .\venv\Scripts\pip install -r requirements.txt
   .\venv\Scripts\python.exe -m playwright install chromium
   ```

### 🌍 Global Execution (Highly Recommended)
ULTINT features a smart process-switcher! You can alias the script globally into your PATH, and it will automatically dive into its isolated `venv` no matter where you currently are in the terminal:

*Linux/macOS (Bash/Zsh):*
```bash
chmod +x ultint.py
# If using Bash (Default Linux):
echo "alias ultint='$(pwd)/ultint.py'" >> ~/.bashrc && source ~/.bashrc

# If using Zsh (Default macOS):
echo "alias ultint='$(pwd)/ultint.py'" >> ~/.zshrc && source ~/.zshrc
```

*Windows (PowerShell):*
```powershell
if (!(Test-Path -Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force }
$ultintPath = "$(Get-Location)\ultint.py"
$venvPath = "$(Get-Location)\venv\Scripts\python.exe"
Add-Content -Path $PROFILE -Value "function ultint { & `"$venvPath`" `"$ultintPath`" `$args }"
. $PROFILE
```

*You can now simply type `ultint` anywhere in your terminal to boot the UI!*

---

## 🛠️ Usage Cheat Sheet

Launch the interactive prompt:
```bash
ultint
```

Inside the console, you will be presented with a persistent `ultint >` shell. 

**Quick Commands for NCL:**
- `crypto crack 5eba2a3bd512a865668e21ab1701b97b` - Executes the dictionary attack engine.
- `crypto magic 566d307764475668636e4a30` - Attempts auto-recursive decryption.
- `crypto xor my_super_secret_key <data>` - Executes an XOR rolling cipher.
- `recon scan 8.8.8.8` - Runs the full 6-phase automated infrastructure scan.
- `recon dns example.com` - Deep DNS enumeration + subdomain discovery.
- `recon headers example.com` - HTTP header fingerprinting and security audit.
- `recon wayback example.com` - Scrapes historical ghost endpoints from Archive.org.
- `social email target@gmail.com` - Checks database leaks and APIs for account registrations.
- `social username JohnDoe123` - Sweeps 400+ platforms for account hits in under 5 seconds.
- `forensics analyze suspect_image.jpg` - Runs the full 7-phase forensic analysis pipeline.
- `forensics stegcrack suspect_image.jpg` - Dictionary brute-force against steghide-embedded file.
- `instagram` - Swaps your shell into the IG-Detective NLP/Data Science mode.
- `help` / `exit` - Print the help menu or kill the shell.

---

## 🏗️ Technical Architecture
```text
ULTINT/
├── ultint.py          # The core REPL shell and venv-switcher.
├── install.sh         # One-command installer (Linux/macOS).
├── requirements.txt   # Global dependency manifest.
├── core/
│   ├── crypto.py          # Cryptography UI, BFS Magic algorithm, Hash Cracker.
│   ├── recon.py           # 6-phase infrastructure scan, DNS enum, Header audit, Wayback CDX.
│   ├── forensics.py       # 7-phase forensic pipeline, Steghide brute-force.
│   ├── social.py          # Asyncio Sherlock engine and silent Email trappers.
│   └── sherlock_data.json # Platform definitions for the username OSINT engine.
├── src/               # IG-Detective Data Science & NLP engine.
│   ├── api/
│   │   ├── auth.py        # Session/cookie authentication handler.
│   │   ├── client.py      # Instagram API client (guest + authenticated).
│   │   └── endpoints.py   # Raw API endpoint definitions.
│   ├── cli/
│   │   ├── shell.py       # IGDetectiveShell (cmd2 interactive sub-shell).
│   │   └── formatters.py  # Rich console output formatters and splash screens.
│   ├── core/
│   │   ├── models.py      # Pydantic data models (User, Post, Location).
│   │   ├── cache.py       # On-disk caching layer.
│   │   ├── config.py      # Runtime configuration management.
│   │   └── exceptions.py  # Custom exception hierarchy.
│   └── modules/
│       ├── recon.py       # Profile scraping and post/location extraction.
│       ├── analytics.py   # Temporal DBSCAN, SNA (NetworkX), Stylometry (NLTK).
│       ├── surveillance.py# Real-time profile change monitoring.
│       ├── evasion.py     # Poisson jitter and anti-detection utilities.
│       └── exporter.py    # ZIP data export engine.
└── tests/             # Pytest test suite.
```

## 📜 License
*Educational and Competitive Forensic use only. Always respect Platform Terms of Service and applicable privacy laws when deployed outside of authorized sandbox environments.*

---

## 🧪 Running Tests
```bash
python3 -m pytest
```

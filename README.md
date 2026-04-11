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
* **Keyless Shodan (`idb`)**: Instantly retrieve vulnerable open ports and CVEs against any IP Address absolutely free, utilizing the unauthenticated Shodan InternetDB lookup.
* **Wayback CDX (`wayback`)**: Rips historical URLs and ghost-endpoints from Archive.org.
* **Standard Tooling**: Seamless OS wrappers for `nmap` port scanning and `whois`.

### 🔬 4. Local Forensics (`forensics`)
* **Metadata Parsing (`exif`)**: Cleanly wraps local `exiftool` binaries to dump visual device signatures into beautifully formatted Rich tables.
* **Strings Extraction (`str`)**: Wraps `strings` to identify embedded flag formats in suspected malware binaries.

### 🕵️ 5. IG-Detective Sub-Shell (`instagram`)
Need to dig deeper? Seamlessly switch from standard OSINT into our heavy-duty Data Science framework perfectly designed for analyzing Instagram Data Export JSONs:
* **Stylometry**: Natural Language Processing (NLTK) linguistics to profile a user's language patterns.
* **Social Network Analysis (SNA)**: Identifies the target's "Inner Circle" via NetworkX graph charting.
* **Temporal Intelligence**: Machine Learning (DBSCAN) spatial anomaly detection to unearth the target's precise timezone and biological sleep schedule.

---

## 🚀 Installation & Setup

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
mkdir -p ~/.local/bin
ln -sf $(pwd)/ultint.py ~/.local/bin/ultint
chmod +x ultint.py
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
- `crypto enc xor my_super_secret_key <data>` - Executes an XOR rolling cipher.
- `recon idb 8.8.8.8` - Instantly returns open ports without ever touching the target server.
- `social email target@gmail.com` - Checks database leaks and APIs for account registrations.
- `social username JohnDoe123` - Sweeps 400+ platforms for account hits in under 5 seconds.
- `forensics exif suspect_image.jpg` - Dumps the embedded camera metadata.
- `instagram` - Swaps your shell into the IG-Detective NLP/Data Science mode.
- `help` / `exit` - Print the help menu or kill the shell.

---

## 🏗️ Technical Architecture
```text
ULTINT/
├── ultint.py          # The core REPL shell and venv-switcher.
├── requirements.txt   # Global dependency manifest.
├── core/
│   ├── crypto.py      # Cryptography UI, BFS Magic algorithm, Hash Cracker.
│   ├── recon.py       # Shodan IDB, Wayback CDX, Nmap APIs.
│   ├── forensics.py   # System binary wrappers (exiftool, strings).
│   └── social.py      # Asyncio Sherlock framework and Email trappers.
└── tests/             # Deep Pytest implementation suite.
└── src/               # The raw Data Science & NLP engine (Imported from IG-Detective).
```

## 📜 License
*Educational and Competitive Forensic use only. Always respect Platform Terms of Service and applicable privacy laws when deployed outside of authorized sandbox environments.*

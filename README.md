# ULTINT 🕵️‍♂️💻
**The Ultimate OSINT & Forensics Interactive Platform**

ULTINT is a premium, locally hosted, fully interactive Command-Line Interface (CLI/TUI) framework designed for TraceLabs, CTFs, and deep digital forensics. 

Constructed in Python and stylized using the `rich` UI library, ULTINT provides an aesthetically pleasing, highly modular workspace that integrates traditional network reconnaissance with cutting-edge Deep OSINT tools like the embedded **IG-Detective** module.

---

## ⚡ Features

### 🧩 Core Modules
- **Crypto & Magic Decoding (`crypto`)**: A "CyberChef-lite" built straight into your terminal. Execute base64, hex, ROT13, and URL decoding. **Auto-Magic Mode** uses a Breadth-First Search (BFS) algorithm to recursively unwrap multi-layer encoded strings up to 5 layers deep until human-readable text is discovered.
- **Forensics (`forensics`)**: Wrapper interactions for local binary analysis, including embedded `exiftool` metadata parsing and `strings` extraction from suspected payloads.
- **Reconnaissance (`recon`)**: Execute lightning-fast WHOIS lookups and NMAP port scanning, alongside a completely keyless **Shodan InternetDB API** lookup (`idb`) and an **Archive.org Wayback Machine** ghost-endpoint extractor (`wayback`).
- **Social & Identity (`social`)**: Hunt targeting usernames across multiple social footprints.

### 🕵️ Instagram Deep Analysis (IG-Detective Sub-Shell)
Seamlessly switch from standard OSINT into the heavy-duty **IG-Detective** environment by typing `instagram`. 
This boots a Playwright-stealth backed sub-shell offering Data Science modules:
- **Stylometry**: Linguistic profiling powered by NLTK.
- **SNA (Social Network Analysis)**: Node-based graphing using NetworkX to identify a target's core "Inner Circle".
- **Temporal**: Machine Learning (DBSCAN) calculation to unearth the target's timezone and sleep schedule.

---

## 🚀 Installation & Setup

1. **Clone the repository**
   ```bash
   git clone ganzvu/ULTINT.git
   cd ULTINT
   ```

2. **Initialize the Virtual Environment**
   ULTINT heavily utilizes a virtual environment (`venv`) to keep complex data science dependencies (pandas, scikit-learn, networkx) isolated from your system packages.
   ```bash
   python3 -m venv venv
   ```

3. **Install Dependencies & Playwright**
   ```bash
   ./venv/bin/pip install -r requirements.txt
   ./venv/bin/python3 -m playwright install chromium
   ```

### 🌍 Global Execution (Optional but Recommended)
ULTINT features smart environment handling! If you create a symbolic link into your path, the script will automatically switch processes into the `venv` no matter where you execute it from.

```bash
mkdir -p ~/.local/bin
ln -sf $(pwd)/ultint.py ~/.local/bin/ultint
chmod +x ultint.py
```
*You can now just type `ultint` anywhere in your terminal!*

---

## 🛠️ Usage

Launch the interactive prompt:
```bash
ultint
```

Inside the console, you will be presented with an `ultint >` shell. 

**Quick Commands:**
- `crypto magic 566d307764475668636e4a30` - Attempts auto-recursive decryption.
- `forensics exif image.jpg` - Extracts beautiful EXIF tables.
- `instagram` - Swaps your shell into the IG-Detective mode.
- `help` - Lists all available modules.
- `exit` - Close the tool.

---

## 🏗️ Architecture
```text
ULTINT/
├── ultint.py          # The core REPL shell and venv-switcher.
├── requirements.txt   # Global dependency manifest.
├── core/
│   ├── crypto.py      # BFS algorithm and Hash logic.
│   ├── recon.py       # Infrastructure tooling.
│   ├── forensics.py   # File diagnostics.
│   └── social.py               
└── src/               # The raw Data Science & Web Scraping engine (Imported from IG-Detective)
```

## 📜 License
Educational and Forensic use only. Always respect Platform Terms of Service and applicable privacy laws when tracing digital footprints.

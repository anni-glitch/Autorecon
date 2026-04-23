# AutoRecon Enterprise 🚀

AutoRecon Enterprise is a professional-grade, asynchronous reconnaissance orchestration platform and Vulnerability SaaS. It transforms traditional CLI-based target enumeration into a high-performance, multi-tenant web application equipped with advanced offensive capabilities, continuous monitoring, and temporal diffing.

## 🌟 Key Features

*   **Asynchronous Engine**: Built on `FastAPI` and `httpx`, the engine executes DNS enumeration, Port Scanning, OSINT, and SSL checks concurrently with extreme speed.
*   **Offensive Mechanics**:
    *   **Subdomain Takeovers**: Dynamically hunts for orphaned `CNAME` records across AWS, GitHub Pages, Heroku, etc.
    *   **Git & Secret Exfiltration**: Deeply parses discovered `.env`, `config.php`, and `.git/config` files using regex to automatically extract exposed AWS keys, Bearer tokens, and Database URIs.
    *   **Evasive Proxy Rotator**: Wraps all outbound requests in exponential backoff logic to survive `429 Too Many Requests` bans (e.g., from Cloudflare).
*   **Enterprise Dashboard**: A dynamic glassmorphic UI featuring a dark/light mode toggle.
*   **Temporal Diff Engine**: Calculates the delta between historical scans, instantly highlighting *New* vs *Resolved* vulnerabilities over time.
*   **Continuous Monitoring**: Integrated `APScheduler` allows you to bind background cron jobs for daily automated scans.
*   **Visual Analytics**: Real-time topological attack surface mapping powered by `Vis.js`.
*   **Headless CI/CD**: Dual-mode authentication supports both cookie-based web sessions and strict `X-API-Key` headers for headless scripting integration.

## 🛠️ Technology Stack

*   **Backend**: Python 3.10+, FastAPI, SQLAlchemy, APScheduler, HTTPX (Async)
*   **Frontend**: HTML5, Vanilla CSS, JS, Vis.js (Attack Graphs), Chart.js (Analytics)
*   **Security**: Passlib (Bcrypt), Python-JOSE (JWT), SlowAPI (Rate Limiting)

## 🚀 Quick Start

### 1. Installation
Clone the repository and install the requirements.
```bash
git clone https://github.com/yourusername/autorecon-enterprise.git
cd autorecon-enterprise
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configuration
Copy the environment template and configure your keys (if any).
```bash
cp .env.example .env
```

### 3. Run the Server
Launch the asynchronous web application.
```bash
uvicorn webapp:app --host 127.0.0.1 --port 8000
```
Navigate to `http://127.0.0.1:8000/login` and register your first account!

## 📸 Screenshots


## ⚠️ Legal Disclaimer
This tool is strictly for educational purposes and authorized penetration testing. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always obtain explicit permission before scanning any networks.

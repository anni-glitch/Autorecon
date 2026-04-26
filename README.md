# AutoRecon Enterprise 🚀

AutoRecon Enterprise is a professional-grade, asynchronous reconnaissance orchestration platform and Vulnerability SaaS. It transforms traditional CLI-based target enumeration into a high-performance, multi-tenant web application equipped with advanced offensive capabilities, continuous monitoring, and temporal diffing.

## 🌟 Key Features

*   **Asynchronous Engine**: Built on `FastAPI` and `httpx`, the engine executes DNS enumeration, Port Scanning, OSINT, and SSL checks concurrently with extreme speed.
*   **Professional PDF Reporting**: Generate board-ready, high-fidelity security reports via `reportlab`. Reports include executive summaries, severity badges, and categorized findings.
*   **Explorer-Style History**: Manage hundreds of scans effortlessly with a folder-based Scan Explorer that automatically groups jobs by target domain.
*   **Local Nmap Power**: Seamlessly integrates with your local Nmap installation to find open ports and running services with enterprise accuracy.
*   **Smart Target Sanitization**: Input full URLs (https://...) or raw hostnames; the platform automatically sanitizes targets to prevent scanning errors.
*   **Temporal Diff Engine**: Calculates the delta between historical scans, instantly highlighting *New* vs *Resolved* vulnerabilities over time.
*   **Diagnostic Intelligence**: Built-in troubleshooting that identifies missing dependencies (like Nmap) and provides human-readable setup guides.
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
<img width="1917" height="872" alt="Screenshot 2026-04-26 160907" src="https://github.com/user-attachments/assets/7db57806-e4fe-470a-b150-ae29bcc9b357" />

<img width="799" height="530" alt="Screenshot 2026-04-26 160956" src="https://github.com/user-attachments/assets/7f3077b7-98d8-471a-9b1a-cdf61690980f" />

<img width="804" height="757" alt="Screenshot 2026-04-26 161230" src="https://github.com/user-attachments/assets/419abfa0-8d7a-42ab-9e62-6f3414f75915" />

<img width="690" height="792" alt="Screenshot 2026-04-26 161308" src="https://github.com/user-attachments/assets/3ff14d74-3494-44c6-81a7-1d71ea2c0336" />

<img width="615" height="399" alt="Screenshot 2026-04-26 161608" src="https://github.com/user-attachments/assets/100bba50-2338-4213-a41f-2d27bc13095b" />

## ⚠️ Legal Disclaimer
This tool is strictly for educational purposes and authorized penetration testing. The developers assume no liability and are not responsible for any misuse or damage caused by this program. Always obtain explicit permission before scanning any networks.

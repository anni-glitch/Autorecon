VERSION = "1.0.0"

DEFAULT_TIMEOUT = 10
DEFAULT_THREADS = 10
DEFAULT_OUTPUT_DIR = "./reports"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

RISKY_PORTS = {
    21: ("FTP", "high"),
    23: ("Telnet", "high"),
    25: ("SMTP", "medium"),
    3306: ("MySQL", "medium"),
    3389: ("RDP", "high"),
    5432: ("PostgreSQL", "medium"),
    5900: ("VNC", "high"),
    6379: ("Redis", "medium"),
    27017: ("MongoDB", "medium"),
}

SENSITIVE_PATHS = [
    "admin", "login", "dashboard", "panel", "wp-admin", "wp-login.php",
    "administrator", ".git", ".git/config", ".env", ".htaccess", ".htpasswd",
    "backup", "backup.zip", "backup.sql", "db.sql", "database.sql",
    "config", "config.php", "config.yml", "config.json", "settings.py",
    "web.config", "api", "api/v1", "api/v2", "swagger", "swagger-ui.html",
    "api-docs", "graphql", "robots.txt", "sitemap.xml", "crossdomain.xml",
    "security.txt", ".well-known/security.txt", "phpinfo.php", "info.php",
    "test.php", "shell.php", "upload", "uploads", "files", "static",
    "assets", "debug", "trace", "actuator", "health", "metrics",
    "console", "phpmyadmin", "adminer", "jenkins", "kibana", "grafana", "jira",
]

CRITICAL_PATHS = [".git", ".env", ".htpasswd", "phpinfo.php", "shell.php"]
HIGH_PATHS = ["admin", "wp-admin", "phpmyadmin", "adminer", "jenkins", "console", "dashboard"]

COMMON_EMAIL_PREFIXES = [
    "info", "admin", "contact", "security", "webmaster",
    "support", "hello", "abuse", "noreply", "postmaster",
]

SECURITY_HEADERS_REQUIRED = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

INFO_LEAKING_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
    "X-Runtime",
    "X-Version",
]

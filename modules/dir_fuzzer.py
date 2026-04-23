import asyncio
import httpx
import re
from config import SENSITIVE_PATHS
from modules.base import BaseModule, FindingResult

SECRET_PATTERNS = {
    "AWS Access Key": r"(?i)AKIA[0-9A-Z]{16}",
    "Database URI": r"(?i)(postgres|mysql|mongodb)://[a-zA-Z0-9]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+(/[a-zA-Z0-9_-]*)?",
    "Generic API Key": r"(?i)(api[_-]?key[\s:=]+['\"]?)([a-zA-Z0-9_-]{20,})",
    "Bearer Token": r"(?i)(bearer\s+)(ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"
}

class DirFuzzerModule(BaseModule):
    name = "dir_fuzzer"
    description = "Discovers hidden directories, sensitive files, and auto-exfiltrates exposed secrets"
    phase = 2

    async def run(self, target: str, custom_wordlist: list = None) -> list[FindingResult]:
        findings = []
        client = self.client
        cleanup = False
        if not client:
            client = httpx.AsyncClient(verify=False)
            cleanup = True
            
        sem = asyncio.Semaphore(20)
        
        async def fetch_path(path):
            url = f"https://{target}/{path}"
            async with sem:
                try:
                    resp = await client.get(url, timeout=10, follow_redirects=False)
                    if resp.status_code in [200, 301, 302, 403]:
                        return path, resp.status_code, len(resp.content), resp.text
                except Exception:
                    pass
            return None
            
        paths_to_test = custom_wordlist if custom_wordlist else SENSITIVE_PATHS
        tasks = [fetch_path(p) for p in paths_to_test]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                path, status, length, text_content = res
                
                # Rule logic
                severity = "low"
                
                critical_matches = [".git", ".env", ".htpasswd", "config.", "backup.", ".sql", "phpinfo.php", "shell.php"]
                high_matches = ["admin", "wp-admin", "phpmyadmin", "adminer", "jenkins", "console"]
                
                secrets_found = []
                
                if status == 200:
                    if any(c in path for c in critical_matches):
                        severity = "critical"
                        # Hunt for secrets inside files
                        for name, pattern in SECRET_PATTERNS.items():
                            matches = re.finditer(pattern, text_content)
                            for match in matches:
                                secrets_found.append(f"{name}: {match.group(0)[:5]}***")
                    elif any(h in path for h in high_matches):
                        severity = "high"
                elif status == 403:
                    severity = "medium"
                    
                desc = f"Status: {status}, Size: {length} bytes"
                if secrets_found:
                    desc += "\nCRITICAL: Automatically exfiltrated targets:\n" + "\n".join(secrets_found)
                    
                findings.append(FindingResult(
                    module=self.name, target=target, category="Hidden Path", severity=severity,
                    title=f"Path Found: /{path}",
                    description=desc,
                    data={"path": f"/{path}", "status_code": status, "content_length": length, "secrets": list(set(secrets_found))}
                ))
                
        if cleanup:
            await client.aclose()
            
        return findings

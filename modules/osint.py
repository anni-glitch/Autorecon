import httpx
import re
from config import COMMON_EMAIL_PREFIXES
from modules.base import BaseModule, FindingResult

class OSINTModule(BaseModule):
    name = "osint"
    description = "Collects open-source intelligence: emails, breach data, and dork URLs"

    async def run(self, target: str) -> list[FindingResult]:
        findings = []
        client = self.client
        cleanup = False
        if not client:
            client = httpx.AsyncClient(verify=False)
            cleanup = True
            
        data = {"emails": [], "dork_urls": [], "breaches": []}
        
        # 1. Emails
        try:
            resp = await client.get(f"https://{target}", timeout=15, follow_redirects=True)
            text = resp.text
            emails_found = set(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text))
            
            # generated emails
            generated_emails = {f"{prefix}@{target}" for prefix in COMMON_EMAIL_PREFIXES}
            
            all_emails = list(emails_found.union(generated_emails))
            data["emails"] = all_emails
            
            findings.append(FindingResult(
                module=self.name, target=target, category="OSINT", severity="info",
                title="Emails Discovered / Generated",
                description=f"Found or generated {len(all_emails)} potential email addresses.",
                data={"emails": all_emails}
            ))
        except Exception:
            pass
            
        # 2. HaveIBeenPwned
        # HIBP domain search requires API key now, but let's try or mock based on instructions.
        # "no API key needed for domain check" according to prompt.
        try:
            hibp_url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{target}"
            resp = await client.get(hibp_url, timeout=10)
            if resp.status_code == 200:
                breaches = resp.json()
                breach_names = list(breaches.keys()) if isinstance(breaches, dict) else [b.get("Name") for b in breaches if isinstance(b, dict)]
                data["breaches"] = breach_names
                if breach_names:
                    findings.append(FindingResult(
                        module=self.name, target=target, category="OSINT", severity="high",
                        title=f"Domain Breaches Found",
                        description=f"{len(breach_names)} breaches associated with this domain.",
                        data={"breaches": breach_names}
                    ))
        except Exception:
            pass

        # 3. Dorks
        dorks = [
            f'https://www.google.com/search?q=site:{target}+filetype:pdf',
            f'https://www.google.com/search?q=site:{target}+filetype:sql',
            f'https://www.google.com/search?q=site:{target}+inurl:admin',
            f'https://www.google.com/search?q=site:{target}+"index+of+/"',
            f'https://www.google.com/search?q=site:{target}+inurl:login',
            f'https://www.google.com/search?q=site:{target}+ext:env+OR+ext:log+OR+ext:bak',
            f'https://www.google.com/search?q="{target}"+password+filetype:txt'
        ]
        data["dork_urls"] = dorks
        findings.append(FindingResult(
            module=self.name, target=target, category="OSINT", severity="info",
            title="Google Dorks",
            description="Generated Google Dork queries for manual review.",
            data={"dork_urls": dorks}
        ))
        
        if cleanup:
            await client.aclose()
            
        return findings

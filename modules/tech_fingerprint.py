import httpx
from bs4 import BeautifulSoup
from modules.base import BaseModule, FindingResult

class TechFingerprintModule(BaseModule):
    name = "tech_fingerprint"
    description = "Identifies technologies, frameworks, and CMS in use"

    async def run(self, target: str) -> list[FindingResult]:
        findings = []
        client = self.client
        cleanup = False
        if not client:
            client = httpx.AsyncClient(verify=False)
            cleanup = True
            
        try:
            url = f"http://{target}"
            resp = await client.get(url, timeout=15, follow_redirects=True)
            html = resp.text
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
            soup = BeautifulSoup(html, "html.parser")
            
            detected = []
            
            # Headers
            server = headers.get("server", "")
            if "nginx" in server: detected.append(("Nginx", "Header"))
            if "apache" in server: detected.append(("Apache", "Header"))
            if "iis" in server: detected.append(("IIS", "Header"))
            if "caddy" in server: detected.append(("Caddy", "Header"))
            
            powered = headers.get("x-powered-by", "")
            if "php" in powered: detected.append(("PHP", "Header"))
            if "asp.net" in powered: detected.append(("ASP.NET", "Header"))
            if "express" in powered: detected.append(("Express", "Header"))
            
            # Meta tags
            generator = ""
            meta_gen = soup.find("meta", attrs={"name": "generator"})
            if meta_gen and meta_gen.get("content"):
                generator = meta_gen["content"].lower()
                
            if "wordpress" in generator: detected.append(("WordPress", "Meta Generator"))
            elif "drupal" in generator: detected.append(("Drupal", "Meta Generator"))
            elif "joomla" in generator: detected.append(("Joomla", "Meta Generator"))
            elif "ghost" in generator: detected.append(("Ghost", "Meta Generator"))
            elif "hugo" in generator: detected.append(("Hugo", "Meta Generator"))
            elif "jekyll" in generator: detected.append(("Jekyll", "Meta Generator"))
            
            # Scripts
            scripts = [s.get('src', '').lower() for s in soup.find_all("script") if s.get('src')]
            script_str = " ".join(scripts)
            
            if "jquery" in script_str: detected.append(("jQuery", "Script Source"))
            if "react" in script_str: detected.append(("React", "Script Source"))
            if "angular" in script_str: detected.append(("Angular", "Script Source"))
            if "vue" in script_str: detected.append(("Vue.js", "Script Source"))
            if "backbone" in script_str: detected.append(("Backbone.js", "Script Source"))
            if "bootstrap" in script_str: detected.append(("Bootstrap", "Script Source"))
            if "tailwind" in script_str: detected.append(("Tailwind CSS", "Script Source"))
            
            # Cookies
            cookies = resp.cookies.keys()
            for c in cookies:
                c = c.lower()
                if c == "phpsessid": detected.append(("PHP", "Cookie"))
                if c == "jsessionid": detected.append(("Java", "Cookie"))
                if "laravel_session" in c: detected.append(("Laravel", "Cookie"))
                if "csrftoken" in c: detected.append(("Django", "Cookie"))
                if "_rails_session" in c: detected.append(("Ruby on Rails", "Cookie"))
                
            # Body patterns
            if "wp-content" in html: detected.append(("WordPress", "Body Pattern"))
            if "Joomla" in html: detected.append(("Joomla", "Body Pattern"))
            if "Drupal.settings" in html: detected.append(("Drupal", "Body Pattern"))
            
            # Deduplicate
            unique_tech = {}
            for tech, source in detected:
                if tech not in unique_tech:
                    unique_tech[tech] = source
                    
            for tech, source in unique_tech.items():
                findings.append(FindingResult(
                    module=self.name, target=target, category="Technology", severity="info",
                    title=f"Detected: {tech}", description=f"Identified via {source}.",
                    data={"technology": tech, "confidence": "high", "source": source}
                ))
                
        except Exception as e:
            err_msg = str(e)
            if "ConnectTimeout" in err_msg:
                err_msg = "Connection timed out. The target may be blocking requests or is offline."
            elif "ConnectError" in err_msg:
                err_msg = "Connection refused. Target web server might be down."
            
            findings.append(FindingResult(
                module=self.name, target=target, category="Error", severity="info",
                title="Fingerprinting Failed", description=err_msg
            ))
            
        finally:
            if cleanup:
                await client.aclose()
                
        return findings

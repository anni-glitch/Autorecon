import asyncio
import httpx
from modules.base import BaseModule, FindingResult
import dns.asyncresolver

TAKEOVER_SIGNATURES = {
    "NoSuchBucket": "AWS S3",
    "There isn't a GitHub Pages site here.": "GitHub Pages",
    "No such app": "Heroku",
    "Do you want to register": "WordPress.com",
    "We could not find what you're looking for": "Pantheon"
}
TAKEOVER_CNAMES = ["s3.amazonaws.com", "github.io", "herokuapp.com", "wordpress.com", "pantheonsite.io"]

class SubdomainFinderModule(BaseModule):
    name = "subdomain_finder"
    description = "Discovers subdomains and tests for critical Subdomain Takeovers"

    async def run(self, target: str) -> list[FindingResult]:
        findings = []
        found_subdomains = set()
        resolver = dns.asyncresolver.Resolver()
        
        client = self.client
        cleanup = False
        if not client:
            client = httpx.AsyncClient(verify=False)
            cleanup = True
            
        sem = asyncio.Semaphore(20)

        async def check_takeover(subdomain: str) -> FindingResult | None:
            try:
                cnames = await resolver.resolve(subdomain, "CNAME")
                cname_target = str(cnames[0]).lower()
                if any(c in cname_target for c in TAKEOVER_CNAMES):
                    resp = await client.get(f"http://{subdomain}", timeout=10, follow_redirects=True)
                    for sig, provider in TAKEOVER_SIGNATURES.items():
                        if sig in resp.text:
                            return FindingResult(
                                module=self.name, target=target, category="Subdomain Takeover", severity="critical",
                                title=f"Takeover Vulnerability: {provider}", 
                                description=f"{subdomain} points to orphaned {provider} resource at {cname_target}",
                                data={"subdomain": subdomain, "cname": cname_target, "provider": provider}
                            )
            except Exception:
                pass
            return None

        # 1. crt.sh
        crt_results = await self._check_crtsh(target, client)
        for sub in crt_results:
            if sub not in found_subdomains:
                found_subdomains.add(sub)
                findings.append(FindingResult(
                    module=self.name, target=target, category="Subdomain", severity="info",
                    title="Subdomain Found via crt.sh", description=sub,
                    data={"subdomain": sub, "source": "crt.sh"}
                ))
        
        # 2. Brute force
        wordlist_path = "wordlists/subdomains.txt"
        prefixes = []
        try:
            with open(wordlist_path, "r") as f:
                prefixes = [line.strip() for line in f if line.strip()]
        except Exception:
            pass
            
        async def check_prefix(prefix):
            subdomain = f"{prefix}.{target}"
            async with sem:
                try:
                    answers = await resolver.resolve(subdomain, "A")
                    ip = str(answers[0])
                    if subdomain not in found_subdomains:
                        found_subdomains.add(subdomain)
                        findings.append(FindingResult(
                            module=self.name, target=target, category="Subdomain", severity="info",
                            title="Subdomain Found via Bruteforce", description=f"{subdomain} -> {ip}",
                            data={"subdomain": subdomain, "source": "wordlist", "ip": ip}
                        ))
                except Exception:
                    pass

        tasks = [check_prefix(p) for p in prefixes]
        await asyncio.gather(*tasks)

        # 3. Takeover Evaluation on all discovered subdomains
        takeover_tasks = [check_takeover(sub) for sub in found_subdomains]
        takeover_results = await asyncio.gather(*takeover_tasks)
        for t_res in takeover_results:
            if t_res:
                findings.append(t_res)

        if cleanup:
            await client.aclose()
            
        return findings

    async def _check_crtsh(self, target: str, client: httpx.AsyncClient) -> set:
        subs = set()
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            resp = await client.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name_value = entry.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip()
                        if name.startswith("*."):
                            name = name[2:]
                        if name.endswith(target) and name != target:
                            subs.add(name)
        except Exception:
            pass
        return subs

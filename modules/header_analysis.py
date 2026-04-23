import httpx
from config import SECURITY_HEADERS_REQUIRED, INFO_LEAKING_HEADERS
from modules.base import BaseModule, FindingResult

class HeaderAnalysisModule(BaseModule):
    name = "header_analysis"
    description = "Analyzes HTTP response headers for security misconfigurations"

    async def run(self, target: str) -> list[FindingResult]:
        findings = []
        client = self.client
        cleanup = False
        if not client:
            client = httpx.AsyncClient(verify=False)
            cleanup = True

        urls = [f"http://{target}", f"https://{target}"]
        
        for url in urls:
            try:
                resp = await client.get(url, timeout=10, follow_redirects=True)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                
                # Check missing security headers
                for header in SECURITY_HEADERS_REQUIRED:
                    if header.lower() not in headers:
                        severity = "low"
                        if header == "Content-Security-Policy":
                            severity = "medium"
                        elif header in ["Referrer-Policy", "Permissions-Policy"]:
                            severity = "info"
                            
                        findings.append(FindingResult(
                            module=self.name, target=target, category="Security Header Missing",
                            severity=severity, title=f"Missing {header}",
                            description=f"The {header} header is missing from {url}",
                            data={"url": url, "header": header}
                        ))
                
                # Check info leaking headers
                for header in INFO_LEAKING_HEADERS:
                    if header.lower() in headers:
                        severity = "low"
                        if header in ["X-Powered-By", "X-AspNet-Version"]:
                            severity = "medium"
                            
                        findings.append(FindingResult(
                            module=self.name, target=target, category="Information Leak",
                            severity=severity, title=f"Info Leaking Header: {header}",
                            description=f"Header {header} found at {url} with value {headers[header.lower()]}",
                            data={"url": url, "header": header, "value": headers[header.lower()]}
                        ))
            except Exception as e:
                findings.append(FindingResult(
                    module=self.name, target=target, category="Error", severity="info",
                    title=f"Error analyzing {url}", description=str(e)
                ))
                
        if cleanup:
            await client.aclose()
            
        return findings

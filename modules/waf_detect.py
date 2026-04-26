import httpx
from modules.base import BaseModule, FindingResult

class WAFDetectModule(BaseModule):
    name = "waf_detect"
    description = "Detects presence and type of Web Application Firewall"
    phase = 2

    async def run(self, target: str) -> list[FindingResult]:
        findings = []
        client = self.client
        cleanup = False
        if not client:
            client = httpx.AsyncClient(verify=False)
            cleanup = True
            
        try:
            url_normal = f"https://{target}/?q=normal"
            url_sqli = f"https://{target}/?id=1' OR '1'='1"
            url_xss = f"https://{target}/?q=<script>alert(1)</script>"
            
            resp_normal = await client.get(url_normal, timeout=10)
            resp_threat = await client.get(url_xss, timeout=10) # Testing XSS
            
            # WAF signatures
            waf_detected = None
            method = ""
            
            headers_threat = {k.lower(): v.lower() for k, v in resp_threat.headers.items()}
            body_threat = resp_threat.text.lower()
            
            if "cf-ray" in headers_threat or "cloudflare" in body_threat:
                waf_detected = "Cloudflare"
                method = "CF-Ray header or body"
            elif "x-amzn-requestid" in headers_threat or "aws waf" in body_threat:
                waf_detected = "AWS WAF"
                method = "AWS headers or body"
            elif any(k.startswith("x-akamai") for k in headers_threat) or ("access denied" in body_threat and "akamai" in headers_threat.get("server", "")):
                waf_detected = "Akamai"
                method = "Akamai headers"
            elif "x-sucuri-id" in headers_threat:
                waf_detected = "Sucuri"
                method = "Sucuri header"
            elif "modsecurity" in body_threat or "mod_security" in body_threat:
                waf_detected = "ModSecurity"
                method = "Body indicator"
            elif "x-iinfo" in headers_threat or "incapsula" in body_threat:
                waf_detected = "Imperva / Incapsula"
                method = "Imperva headers"
            elif "barracuda" in body_threat:
                waf_detected = "Barracuda"
                method = "Body indicator"
            elif resp_threat.status_code in [403, 406] and resp_normal.status_code == 200:
                waf_detected = "Generic WAF / IPS"
                method = f"Blocked payload with {resp_threat.status_code}"
                
            if waf_detected:
                findings.append(FindingResult(
                    module=self.name, target=target, category="WAF", severity="info",
                    title=f"WAF Detected: {waf_detected}",
                    description=f"Detected via {method}",
                    data={"waf": waf_detected, "detection_method": method}
                ))
            else:
                findings.append(FindingResult(
                    module=self.name, target=target, category="WAF", severity="low",
                    title="No WAF Detected",
                    description="No known WAF signature matched.",
                    data={"waf": "None"}
                ))
                
        except httpx.RequestError as e:
            findings.append(FindingResult(
                module=self.name, target=target, category="Error", severity="info",
                title="Error detecting WAF", description=str(e)
            ))
        except Exception as e:
            findings.append(FindingResult(
                module=self.name, target=target, category="Error", severity="info",
                title="Unexpected error detecting WAF", description=str(e)
            ))
            
        finally:
            if cleanup:
                await client.aclose()
                
        return findings

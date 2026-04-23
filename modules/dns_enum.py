import dns.asyncresolver
from modules.base import BaseModule, FindingResult

class DNSEnumModule(BaseModule):
    name = "dns_enum"
    description = "Enumerates DNS records: A, AAAA, MX, NS, CNAME, TXT, SOA"

    async def run(self, target: str) -> list[FindingResult]:
        findings = []
        record_types = ["A", "AAAA", "MX", "NS", "CNAME", "TXT", "SOA"]
        # Use asyncresolver for optimization
        resolver = dns.asyncresolver.Resolver()
        
        for record_type in record_types:
            try:
                answers = await resolver.resolve(target, record_type)
                values = [str(rdata) for rdata in answers]
                if values:
                    findings.append(FindingResult(
                        module=self.name,
                        target=target,
                        category="DNS",
                        severity="info",
                        title=f"{record_type} Record Found",
                        description=f"Found {len(values)} {record_type} records.",
                        data={"record_type": record_type, "values": values}
                    ))
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.Timeout:
                findings.append(FindingResult(
                    module=self.name, target=target, category="Error", severity="info",
                    title="DNS Timeout", description=f"Timeout looking up {record_type}"
                ))
            except Exception as e:
                findings.append(FindingResult(
                    module=self.name, target=target, category="Error", severity="info",
                    title=f"Error checking {record_type}", description=str(e)
                ))
                
        return findings

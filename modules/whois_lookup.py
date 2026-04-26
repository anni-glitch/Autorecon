import whois
import asyncio
from datetime import datetime
from modules.base import BaseModule, FindingResult

class WHOISModule(BaseModule):
    name = "whois_lookup"
    description = "Retrieves WHOIS registration data for the target domain"

    async def run(self, target: str) -> list[FindingResult]:
        try:
            # Use asyncio.to_thread because whois is blocking
            domain_info = await asyncio.to_thread(whois.whois, target)
        except Exception as e:
            return [FindingResult(
                module=self.name, target=target, category="Error", severity="info",
                title="WHOIS Error", description=str(e)
            )]
            
        if not domain_info or not domain_info.domain_name:
            return [FindingResult(
                module=self.name, target=target, category="Info", severity="info",
                title="WHOIS Not Found", description="Could not retrieve WHOIS data."
            )]

        exp_date = domain_info.expiration_date
        if isinstance(exp_date, list):
            exp_date = exp_date[0]
            
        severity = "info"
        title = "WHOIS Information"
        
        if exp_date and isinstance(exp_date, datetime):
            days_left = (exp_date - datetime.utcnow()).days
            if days_left <= 90:
                severity = "medium"
                title = "Domain Expiring Soon"
                
        # Clean data (convert dates to strings)
        data = {}
        for k, v in dict(domain_info).items():
            if isinstance(v, list):
                if v and isinstance(v[0], datetime):
                    data[k] = [d.isoformat() for d in v]
                else:
                    data[k] = v
            elif isinstance(v, datetime):
                data[k] = v.isoformat()
            else:
                data[k] = v

        return [FindingResult(
            module=self.name,
            target=target,
            category="WHOIS",
            severity=severity,
            title=title,
            description="WHOIS data retrieved successfully.",
            data=data
        )]

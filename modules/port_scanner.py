import nmap
import asyncio
from config import RISKY_PORTS
from modules.base import BaseModule, FindingResult

class PortScannerModule(BaseModule):
    name = "port_scanner"
    description = "Scans top 1000 TCP ports and identifies open services"
    phase = 2

    async def run(self, target: str) -> list[FindingResult]:
        findings = []
        try:
            nm = nmap.PortScanner()
            # Wrap blocking call in asyncio.to_thread
            await asyncio.to_thread(nm.scan, target, arguments="-T4 --top-ports 1000 -sV")
        except Exception as e:
             err_msg = str(e)
             if "nmap program was not found" in err_msg.lower() or "nmap is not installed" in err_msg.lower():
                 err_msg = "Nmap binary not found on the host system. Please install Nmap (https://nmap.org) and add it to your PATH."
                 title = "Nmap Missing"
             else:
                 title = "Nmap Error"
             
             return [FindingResult(
                module=self.name, target=target, category="Error", severity="info",
                title=title, description=err_msg
            )]
            
        if target not in nm.all_hosts():
            # Try to grab by IP if target was resolved internally by nmap
            hosts = nm.all_hosts()
            if not hosts:
                return []
            scan_data = nm[hosts[0]]
        else:
            scan_data = nm[target]
            
        if 'tcp' not in scan_data:
            return []
            
        for port, port_info in scan_data['tcp'].items():
            if port_info['state'] == 'open':
                service = port_info.get('name', 'unknown')
                version = port_info.get('version', '')
                protocol = 'tcp'
                
                severity = "info"
                if port in RISKY_PORTS:
                    _, severity = RISKY_PORTS[port]
                if port in [21, 23, 5900]:
                    severity = "high"
                    
                findings.append(FindingResult(
                    module=self.name,
                    target=target,
                    category="Open Port",
                    severity=severity,
                    title=f"Open Port {port}/{protocol} ({service})",
                    description=f"Service: {service} {version}",
                    data={"port": port, "protocol": protocol, "service": service, "version": version}
                ))
                
        return findings

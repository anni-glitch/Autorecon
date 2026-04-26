import ssl
import socket
import asyncio
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from modules.base import BaseModule, FindingResult

class SSLCheckModule(BaseModule):
    name = "ssl_check"
    description = "Inspects SSL/TLS certificate for validity, expiry, and configuration issues"

    async def run(self, target: str) -> list[FindingResult]:
        try:
            cert_data = await asyncio.to_thread(self._get_cert, target)
        except Exception as e:
            err_msg = str(e)
            if "Connection refused" in err_msg or "10061" in err_msg:
                err_msg = "Port 443 is closed. Target likely does not support HTTPS."
            return [FindingResult(
                module=self.name, target=target, category="Error", severity="info",
                title="SSL/TLS Not Supported", description=err_msg
            )]
            
        if not cert_data:
            return []

        findings = []
        cert, tls_version, cipher_name = cert_data
        
        # Parse Dates
        not_after_str = cert.get('notAfter')
        if not_after_str:
            try:
                # notAfter from cryptography comes as "Oct 29 11:37:05 2024 GMT"
                expires = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expires - datetime.utcnow()).days
                
                if days_left < 0:
                    findings.append(self._create_finding(target, "critical", "Certificate Expired", f"Expired {abs(days_left)} days ago.", cert_data))
                elif days_left <= 30:
                    findings.append(self._create_finding(target, "high", "Certificate Expiring Soon", f"Expires in {days_left} days.", cert_data))
                elif days_left <= 60:
                    findings.append(self._create_finding(target, "medium", "Certificate Expiring Soon", f"Expires in {days_left} days.", cert_data))
            except Exception:
                pass
                
        # Issuer vs Subject (Self Signed)
        issuer = cert.get('issuer', {})
        subject = cert.get('subject', {})
        
        if issuer == subject and issuer:
            findings.append(self._create_finding(target, "medium", "Self-Signed Certificate", "Issuer matches subject.", cert_data))
            
        # Weak ciphers
        weak_ciphers = ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]
        if any(w in cipher_name for w in weak_ciphers):
            findings.append(self._create_finding(target, "medium", "Weak Cipher Suite", f"Using {cipher_name}", cert_data))
            
        # TLS < 1.2
        if tls_version in ["TLSv1", "TLSv1.1"]:
            findings.append(self._create_finding(target, "high", "Deprecated TLS Version", f"Using {tls_version}", cert_data))
            
        if not findings:
            findings.append(self._create_finding(target, "info", "SSL Valid", f"Valid Certificate. {tls_version}", cert_data))

        return findings

    def _create_finding(self, target, severity, title, desc, cert_data):
        return FindingResult(
            module=self.name, target=target, category="SSL/TLS", severity=severity,
            title=title, description=desc, 
            data={"tls_version": cert_data[1], "cipher": cert_data[2], "issuer": str(cert_data[0].get("issuer")), "expires": cert_data[0].get("notAfter")}
        )

    def _get_cert(self, target: str):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                
        cert_obj = x509.load_der_x509_certificate(der_cert, default_backend())
        
        try:
            subject = {attr.oid._name: attr.value for attr in cert_obj.subject}
        except Exception: subject = {}
        
        try:
            issuer = {attr.oid._name: attr.value for attr in cert_obj.issuer}
        except Exception: issuer = {}
            
        not_after = cert_obj.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT")
        
        cert = {
            "subject": subject,
            "issuer": issuer,
            "notAfter": not_after
        }
        
        return cert, cipher[1], cipher[0]

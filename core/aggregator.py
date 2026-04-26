from modules.base import FindingResult

def aggregate_findings(findings: list[FindingResult]) -> tuple[list[FindingResult], dict]:
    # Deduplicate by (module, title, target)
    unique_findings = {}
    for finding in findings:
        key = (finding.module, finding.title, finding.target)
        if key not in unique_findings:
            unique_findings[key] = finding
    
    deduplicated = list(unique_findings.values())
    
    # Assign risk scores & sort
    severity_scores = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0
    }
    
    deduplicated.sort(key=lambda x: severity_scores.get(x.severity, 0), reverse=True)
    
    # Summary
    summary = {
        "total": len(deduplicated),
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "by_module": {},
        "risk_score": 0
    }
    
    for finding in deduplicated:
        sev = finding.severity
        if sev in summary["by_severity"]:
            summary["by_severity"][sev] += 1
        
        mod = finding.module
        summary["by_module"][mod] = summary["by_module"].get(mod, 0) + 1
        
        summary["risk_score"] += severity_scores.get(sev, 0)
        
    return deduplicated, summary

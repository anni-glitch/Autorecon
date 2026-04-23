import json
import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from modules.base import FindingResult

def generate_reports(target: str, findings: list[FindingResult], summary: dict, output_dir: str = "./reports", template_dir: str = "./templates", no_html: bool = False) -> tuple[str, str | None]:
    os.makedirs(output_dir, exist_ok=True)
    
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(output_dir, f"{target}_{timestamp}.json")
    html_path = os.path.join(output_dir, f"{target}_{timestamp}.html")
    
    # Save JSON
    output_data = {
        "target": target,
        "timestamp": timestamp,
        "summary": summary,
        "findings": [
            {
                "module": f.module,
                "target": f.target,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "data": f.data,
                "timestamp": f.timestamp
            } for f in findings
        ]
    }
    
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=4)
        
    if no_html:
        return json_path, None
        
    # Generate HTML
    try:
        env = Environment(loader=FileSystemLoader(template_dir))
        template = env.get_template("report.html.j2")
        html_content = template.render(
            target=target,
            timestamp=timestamp,
            summary=summary,
            findings=findings,
            datetime=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            version="1.0"
        )
        
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)
    except Exception as e:
        print(f"Error generating HTML report: {e}")
        return json_path, None
        
    return json_path, html_path

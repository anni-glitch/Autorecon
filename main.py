import sys
import asyncio
import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import config
from modules.dns_enum import DNSEnumModule
from modules.subdomain_finder import SubdomainFinderModule
from modules.whois_lookup import WHOISModule
from modules.port_scanner import PortScannerModule
from modules.header_analysis import HeaderAnalysisModule
from modules.ssl_check import SSLCheckModule
from modules.tech_fingerprint import TechFingerprintModule
from modules.waf_detect import WAFDetectModule
from modules.dir_fuzzer import DirFuzzerModule
from modules.osint import OSINTModule
from core.engine import run_engine
from core.aggregator import aggregate_findings
from core.reporter import generate_reports

app = typer.Typer()
console = Console()

AVAILABLE_MODULES = {
    DNSEnumModule.name: DNSEnumModule,
    SubdomainFinderModule.name: SubdomainFinderModule,
    WHOISModule.name: WHOISModule,
    PortScannerModule.name: PortScannerModule,
    HeaderAnalysisModule.name: HeaderAnalysisModule,
    SSLCheckModule.name: SSLCheckModule,
    TechFingerprintModule.name: TechFingerprintModule,
    WAFDetectModule.name: WAFDetectModule,
    DirFuzzerModule.name: DirFuzzerModule,
    OSINTModule.name: OSINTModule
}

def print_banner():
    banner = """
╔═══════════════════════════════════════╗
║         AutoRecon v1.0                ║
║   Automated Reconnaissance Tool       ║
║   Use only on systems you own or      ║
║   have explicit permission to test    ║
╚═══════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")

@app.command()
def scan(
    target: str,
    modules: str = typer.Option(None, "--modules", help="Comma-separated module names to run"),
    output_dir: str = typer.Option(config.DEFAULT_OUTPUT_DIR, "--output-dir"),
    stealth: bool = typer.Option(False, "--stealth/--no-stealth"),
    resume: bool = typer.Option(False, "--resume/--no-resume"),
    threads: int = typer.Option(config.DEFAULT_THREADS, "--threads"),
    timeout: int = typer.Option(config.DEFAULT_TIMEOUT, "--timeout"),
    no_html: bool = typer.Option(False, "--no-html"),
    agree: bool = typer.Option(False, "--agree", help="Acknowledge authorization")
):
    if not agree:
        panel = Panel(
            "AutoRecon is intended for use only on systems you own or have explicit written authorization to test. "
            "Unauthorized scanning is illegal. The authors assume no liability for misuse.\n\n"
            "You MUST pass the --agree flag to confirm authorization.",
            title="Authorization Required", border_style="red"
        )
        console.print(panel)
        raise typer.Exit(code=1)

    print_banner()
    
    selected = []
    if modules:
        for m in [x.strip() for x in modules.split(",")]:
            if m in AVAILABLE_MODULES:
                selected.append(AVAILABLE_MODULES[m])
            else:
                console.print(f"[bold yellow]Warning:[/bold yellow] Module '{m}' not found. Skipping.")
    else:
        selected = list(AVAILABLE_MODULES.values())

    if not selected:
        console.print("[bold red]Error:[/bold red] No valid modules selected.")
        raise typer.Exit(code=1)

    table = Table(title="Modules to Run")
    table.add_column("Module Name", style="cyan")
    table.add_column("Description", style="white")
    for mod_cls in selected:
        table.add_row(mod_cls.name, mod_cls.description)
    console.print(table)
    console.print()

    # Pass global config and httpx client for active requests properly initialized
    limits = httpx.Limits(max_connections=threads, max_keepalive_connections=threads)
    transport_params = {"verify": False}
    
    async def run_async():
        # Instantiate a shared HTTP client
        async with httpx.AsyncClient(timeout=timeout, **transport_params) as client:
            module_instances = [cls(client=client) for cls in selected]
            findings = await run_engine(target, module_instances, max_concurrency=threads, stealth=stealth, resume=resume)
            return findings

    all_findings = asyncio.run(run_async())
    
    dedup_findings, summary = aggregate_findings(all_findings)
    
    # Per module tables
    console.print("\n[bold]Scan Completed. Results by Module:[/bold]\n")
        
    modules_run = list(set([f.module for f in dedup_findings]))
    
    for mod_name in modules_run:
        mod_findings = [f for f in dedup_findings if f.module == mod_name]
        if not mod_findings: continue
        
        t = Table(title=f"Module: {mod_name}")
        t.add_column("Title")
        t.add_column("Severity")
        t.add_column("Description")
        
        for f in mod_findings:
            sev_color = {"critical": "bold white on red", "high": "bold red", "medium": "bold yellow", "low": "bold blue", "info": "cyan"}.get(f.severity, "white")
            t.add_row(f.title, f"[{sev_color}]{f.severity}[/{sev_color}]", f.description)
        console.print(t)
        
    # Summary Table
    json_path, html_path = generate_reports(target, dedup_findings, summary, output_dir=output_dir, no_html=no_html)
    
    summary_text = (
        f"[bold white on red]Critical: {summary['by_severity']['critical']}[/]\n"
        f"[bold red]High: {summary['by_severity']['high']}[/]\n"
        f"[bold yellow]Medium: {summary['by_severity']['medium']}[/]\n"
        f"[bold blue]Low: {summary['by_severity']['low']}[/]\n"
        f"[cyan]Info: {summary['by_severity']['info']}[/]\n\n"
        f"[bold]Total Risk Score: {summary['risk_score']}[/]"
    )
    
    summary_panel = Panel(summary_text, title="Final Risk Summary", border_style="green")
    console.print(summary_panel)
    
    console.print("\n[bold]Reports Generated:[/bold]")
    console.print(f"- JSON: [cyan]{json_path}[/cyan]")
    if html_path:
        console.print(f"- HTML: [cyan]{html_path}[/cyan]")

@app.command()
def list_modules():
    table = Table(title="Available Modules")
    table.add_column("Module Name", style="cyan")
    table.add_column("Description", style="white")
    for mod_cls in AVAILABLE_MODULES.values():
        table.add_row(mod_cls.name, mod_cls.description)
    console.print(table)

@app.command()
def version():
    console.print(f"AutoRecon v{config.VERSION} | Python {sys.version.split()[0]} | Platform {sys.platform}")

if __name__ == "__main__":
    app()

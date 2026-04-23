import asyncio
import os
import json
import httpx
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
from modules.base import FindingResult, BaseModule

class EvasionClientWrapper:
    def __init__(self, proxies=None):
        transport = httpx.AsyncHTTPTransport(retries=2)
        # Using native httpx retries for connection drops, plus custom async logic for 429 backoffs.
        self.client = httpx.AsyncClient(verify=False, proxies=proxies, timeout=15, transport=transport)
    
    async def get(self, *args, **kwargs):
        for attempt in range(3):
            try:
                resp = await self.client.get(*args, **kwargs)
                if resp.status_code == 429:
                    # Cloudflare or typical rate-limit -> Exponential Backoff
                    await asyncio.sleep(2 ** attempt + 2)
                else:
                    return resp
            except httpx.RequestError:
                if attempt == 2:
                    raise
                await asyncio.sleep(1)
        return resp

    async def post(self, *args, **kwargs):
        return await self.client.post(*args, **kwargs)

    async def aclose(self):
        await self.client.aclose()

async def run_engine(
    target: str, 
    activated_modules: list[BaseModule], 
    max_concurrency: int = 10, 
    stealth: bool = False, 
    resume: bool = False, 
    progress_callback=None,
    custom_payloads: dict = None
) -> list[FindingResult]:
    os.makedirs("reports", exist_ok=True)
    checkpoint_file = os.path.join("reports", f".checkpoint_{target}.json")
    
    completed_modules = set()
    all_findings = []
    
    if resume and os.path.exists(checkpoint_file):
        try:
            with open(checkpoint_file, "r") as f:
                checkpoint_data = json.load(f)
                completed_modules = set(checkpoint_data.get("completed_modules", []))
                for item in checkpoint_data.get("findings", []):
                    all_findings.append(FindingResult(**item))
        except Exception:
            pass
            
    modules_to_run = [m for m in activated_modules if m.name not in completed_modules]
    
    if not modules_to_run:
        return all_findings

    # Proxy Hook Parsing
    proxy_url = os.getenv("AUTORECON_PROXY", None)
    proxies = {"all://": proxy_url} if proxy_url else None
    
    # Initialize the Global Master Evasion Client for this run
    global_client = EvasionClientWrapper(proxies=proxies)
    for m in modules_to_run:
        m.client = global_client

    semaphore = asyncio.Semaphore(max_concurrency)
    
    async def run_module_task(module: BaseModule, progress: Progress, task_id):
        async with semaphore:
            if stealth:
                import random
                await asyncio.sleep(random.uniform(1, 4))
                
            progress.update(task_id, description=f"Running {module.name}...", current_module=module.name)
            if progress_callback:
                await progress_callback({"type": "module_start", "module": module.name})
            
            try:
                if module.name == "dir_fuzzer" and custom_payloads and custom_payloads.get("dir_fuzzer"):
                    findings = await module.run(target, custom_wordlist=custom_payloads["dir_fuzzer"])
                else:
                    findings = await module.run(target)
            except Exception as e:
                findings = [FindingResult(
                    module=module.name, target=target, category="Error", severity="info",
                    title="Module Error", description=str(e)
                )]
            
            all_findings.extend(findings)
            completed_modules.add(module.name)
            
            if progress_callback:
                for f_item in findings:
                    await progress_callback({"type": "finding", "module": module.name, "finding": vars(f_item)})
                await progress_callback({"type": "module_finish", "module": module.name})
            
            checkpoint_data = {
                "completed_modules": list(completed_modules),
                "findings": [vars(f) for f in all_findings]
            }
            with open(checkpoint_file, "w") as f:
                json.dump(checkpoint_data, f)
            
            progress.advance(task_id)
            return findings

    try:
        with Progress(
            TextColumn("[bold blue]Scanning {task.fields[target]}"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "•",
            TextColumn("{task.fields[current_module]}"),
            TimeElapsedColumn()
        ) as progress:
            task_id = progress.add_task("Scanning...", total=len(modules_to_run), target=target, current_module="Starting...")
            
            phases = {}
            for m in modules_to_run:
                p = getattr(m, 'phase', 1)
                phases.setdefault(p, []).append(m)
                
            for p in sorted(phases.keys()):
                tasks = []
                for module in phases[p]:
                    tasks.append(run_module_task(module, progress, task_id))
                
                await asyncio.gather(*tasks, return_exceptions=True)
    finally:
        await global_client.aclose()
        
    return all_findings

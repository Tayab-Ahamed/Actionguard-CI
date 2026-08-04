from pathlib import Path
import json,shutil,subprocess
from actionguard.config import TOOL_TIMEOUT
from actionguard.models import Finding,Severity

def run_tool(name,args,cwd:Path):
    exe=shutil.which(name)
    if not exe:return None,'missing'
    try:
        p=subprocess.run([exe,*args],cwd=cwd,text=True,capture_output=True,timeout=TOOL_TIMEOUT)
        return p,p.returncode
    except Exception as e:return None,str(e)
def tool_failure(name,status,category='code_quality'):
    return Finding(f'AG-TOOL-{name.upper()}','actionguard',category,Severity.INFO,f'{name} unavailable or failed','',1,f'Status: {status}','Coverage from this optional scanner is unavailable.',f'Install/configure {name}; other audits completed normally.')

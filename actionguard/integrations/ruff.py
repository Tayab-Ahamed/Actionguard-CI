from pathlib import Path
import json
from actionguard.models import Finding,Severity
from .common import run_tool,tool_failure
def scan(repo):
    if not any(repo.rglob('*.py')): return [],{'status':'skipped'}
    p,s=run_tool('ruff',['check','--output-format=json','.'],repo)
    if not p:return [tool_failure('ruff',s)],{'status':'failed'}
    try:data=json.loads(p.stdout or '[]')
    except:return [tool_failure('ruff','parse error')],{'status':'failed'}
    return [Finding('RUFF-'+x.get('code',''), 'ruff','code_quality',Severity.LOW,x.get('message','Ruff finding'),x.get('filename',''),x.get('location',{}).get('row',1),x.get('message',''),'Maintainability defects can hide security mistakes.',f"Apply Ruff guidance for {x.get('code','the rule')}.",bool(x.get('fix')),bool(x.get('fix'))) for x in data],{'status':'ok','count':len(data)}

from pathlib import Path
from actionguard.models import Finding,Severity
from actionguard.utils.file_utils import iter_files,rel,read_text
DANGEROUS={'.env','.env.local','.env.production','.env.development','.env.staging','.env.test','id_rsa','id_rsa.pub','credentials.json','service-account.json','firebase-adminsdk.json','aws-exports.js','.npmrc','.pypirc'}
REQUIRED_IGNORE=['.env','.env.*','*.pem','*.key','credentials.json','service-account.json']
def scan(repo_path: Path):
    out=[]
    for p in iter_files(repo_path):
        n=p.name; rp=rel(p,repo_path)
        allowed=n in {'.env.example','.env.template'}
        risky=n in DANGEROUS or p.suffix in {'.pem','.key'}
        if allowed:
            out.append(Finding('AG-ENV-INFO','actionguard','secrets',Severity.INFO,'Environment template present',rp,1,'Template file exists.','Templates can accidentally contain real values.','Keep placeholders only; never include live secrets.'))
        elif risky:
            sev=Severity.CRITICAL if n.startswith('.env') or p.suffix in {'.pem','.key'} or n in {'id_rsa','credentials.json','service-account.json','firebase-adminsdk.json'} else Severity.HIGH
            out.append(Finding('AG-ENV-001','actionguard','secrets',sev,'Sensitive configuration file committed',rp,1,f'{rp} is present in the repository.','Credentials may be exposed through source history and artifacts.','Remove the file from tracking, rotate every contained credential, purge history when necessary, and add an ignore rule.',False,False,manual_review_required=True))
    gi=repo_path/'.gitignore'
    if not gi.exists():
        out.append(Finding('AG-ENV-002','actionguard','hygiene',Severity.MEDIUM,'Missing .gitignore','.gitignore',1,'No .gitignore found.','Sensitive local files may be committed.','Create .gitignore with environment and key patterns.',True,True,'+++ .gitignore\n+.env\n+.env.*\n+*.pem\n+*.key\n+credentials.json\n+service-account.json',False))
    else:
        text=read_text(gi) or ''; missing=[x for x in REQUIRED_IGNORE if x not in {ln.strip() for ln in text.splitlines()}]
        if missing:
            patch=''.join(f'+{x}\n' for x in missing)
            out.append(Finding('AG-ENV-003','actionguard','hygiene',Severity.MEDIUM,'Incomplete secret ignore rules','.gitignore',1,'Missing patterns: '+', '.join(missing),'Sensitive files may be committed accidentally.','Add the missing patterns to .gitignore.',True,True,'--- .gitignore\n+++ .gitignore\n'+patch,False))
    return out

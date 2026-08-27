from pathlib import Path
from datetime import datetime, timezone
import html
import json

from actionguard.remediation import checklist, prioritize
from actionguard.scoring import severity_counts

LABEL = {
    "cicd": "CI/CD Workflow Security",
    "agentic": "Agentic AI Workflow Risks",
    "secrets": "Env and Secret Exposure",
    "artifacts": "Artifact Upload Risks",
    "code_quality": "Code Quality",
    "dependencies": "Dependency Vulnerabilities",
    "hygiene": "Repository Hygiene",
}


def build_payload(repo, findings, scores, statuses):
    return {
        "schema_version": "1.0",
        "product": "ActionGuard AutoAudit",
        "repository": repo.name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scores": scores,
        "summary": severity_counts(findings),
        "scanner_status": statuses,
        "findings": [f.to_dict() for f in prioritize(findings)],
        "remediation_plan": checklist(findings),
    }


def write_json(path, payload):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _e(x):
    return html.escape(str(x))


def write_html(path, p):
    findings = p["findings"]
    groups = {k: [f for f in findings if f["category"] == k] for k in LABEL}
    s = p["summary"]
    sc = p["scores"]
    cards = "".join(
        f'<article class="score"><span>{_e(k.replace("_", " ").title())}</span><strong>{v}</strong><small>/ 100</small></article>'
        for k, v in sc.items()
    )
    sev = "".join(f'<span class="chip {k}"><b>{v}</b> {k}</span>' for k, v in s.items())
    critical = (
        "".join(render_f(f) for f in findings if f["severity"] in ("critical", "high"))
        or '<p class="empty">No critical or high findings.</p>'
    )
    sections = "".join(
        f'<section id="{k}"><div class="section-head"><p>{i + 5:02d}</p><h2>{_e(LABEL[k])}</h2><span>{len(groups[k])} findings</span></div>{("".join(render_f(x) for x in groups[k]) or "<p class=empty>No findings in this category.</p>")}</section>'
        for i, k in enumerate(LABEL)
    )
    rem = (
        "".join(
            f'<li><input type="checkbox" disabled><div><b>{_e(x["title"])}</b><p>{_e(x["action"])}</p><small>{_e(x["severity"])} | auto-fix safe: {str(x["auto_fix_safe"]).lower()} | manual review: {str(x["manual_review_required"]).lower()}</small></div></li>'
            for x in p["remediation_plan"]
        )
        or "<li>No remediation required.</li>"
    )
    css = """*{box-sizing:border-box}body{margin:0;background:#fff;color:#2c2c2b;font:16px/1.55 Arial,sans-serif}header,main,footer{max-width:1120px;margin:auto;padding:40px 32px}.eyebrow{color:#2783de;font-weight:700;letter-spacing:.12em;text-transform:uppercase;font-size:13px}h1{font-size:52px;line-height:1.05;max-width:760px;margin:12px 0 20px}h2{font-size:30px;margin:0}.lede{max-width:730px;color:#5f5c57;font-size:19px}.hero{background:#f9f8f7;border-bottom:1px solid #e6e5e3}.meta{display:flex;gap:24px;color:#7d7a75;flex-wrap:wrap}.scores{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:32px 0}.score{border:1px solid #e6e5e3;border-radius:10px;padding:18px;background:#fff}.score span{display:block;color:#7d7a75;font-size:13px}.score strong{font-size:36px}.score small{color:#7d7a75}.chips{display:flex;gap:8px;flex-wrap:wrap}.chip{padding:7px 11px;border-radius:999px;background:#f0efed}.chip.critical,.chip.high{background:#fce9e7;color:#9e2f28}.chip.medium{background:#fbebde;color:#8b4b17}.chip.low,.chip.info{background:#e5f2fc;color:#185c99}section{padding:52px 0;border-top:1px solid #e6e5e3}.section-head{display:grid;grid-template-columns:48px 1fr auto;align-items:baseline;gap:12px;margin-bottom:24px}.section-head p,.section-head span{color:#7d7a75}.finding{border:1px solid #e6e5e3;border-left:4px solid #d5803b;border-radius:8px;padding:20px;margin:12px 0}.finding.critical,.finding.high{border-left-color:#e56458}.finding h3{margin:0 0 6px;font-size:19px}.where{font:13px Consolas,monospace;color:#7d7a75}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:14px}.grid p{margin:4px 0}.grid b{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#7d7a75}.patch{white-space:pre-wrap;background:#191919;color:#fff;padding:14px;border-radius:6px;overflow:auto;font:13px/1.45 Consolas,monospace}.empty{padding:24px;background:#f9f8f7;color:#7d7a75}.checklist{list-style:none;padding:0}.checklist li{display:flex;gap:14px;border-bottom:1px solid #e6e5e3;padding:16px 0}.checklist p{margin:4px 0}.checklist small{color:#7d7a75}footer{color:#7d7a75;border-top:1px solid #e6e5e3}@media(max-width:760px){header,main,footer{padding:28px 20px}h1{font-size:38px}.scores{grid-template-columns:1fr 1fr}.grid{grid-template-columns:1fr}.section-head{grid-template-columns:36px 1fr}.section-head span{grid-column:2}.meta{gap:8px 18px}}@media(prefers-color-scheme:dark){body{background:#191919;color:#fff}.hero,.empty{background:#202020}.score,.finding{background:#202020;border-color:rgba(255,255,255,.2)}section,footer{border-color:rgba(255,255,255,.2)}.lede,.meta,.where,.section-head p,.section-head span,.checklist small{color:rgba(255,255,255,.65)}}"""
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ActionGuard Audit - {_e(p['repository'])}</title><style>{css}</style></head><body><div class="hero"><header><p class="eyebrow">ActionGuard AutoAudit | Security evidence</p><h1>Repository audit for {_e(p['repository'])}</h1><p class="lede">Detection -> evidence -> severity -> remediation. Secret values are redacted by design; dangerous changes are never silently applied.</p><div class="meta"><span>Generated {_e(p['generated_at'])}</span><span>Schema {_e(p['schema_version'])}</span><span>{len(findings)} normalized findings</span></div></header></div><main><section><div class="section-head"><p>01</p><h2>Executive Summary</h2></div><div class="chips">{sev}</div></section><section><div class="section-head"><p>02</p><h2>Scoreboard</h2></div><div class="scores">{cards}</div></section><section><div class="section-head"><p>03</p><h2>Critical Findings</h2></div>{critical}</section>{sections}<section><div class="section-head"><p>12</p><h2>Remediation Plan & Final Priority Checklist</h2></div><ol class="checklist">{rem}</ol></section></main><footer>ActionGuard AutoAudit | zizmor-based CI/CD analysis plus custom security audits.</footer></body></html>"""
    p_path = Path(path)
    p_path.parent.mkdir(parents=True, exist_ok=True)
    p_path.write_text(doc, encoding="utf-8")


def render_f(f):
    patch = f'<pre class="patch">{_e(f.get("patch_preview", ""))}</pre>' if f.get("patch_preview") else ""
    return f"""<article class="finding {_e(f['severity'])}"><h3>{_e(f['severity'].upper())} | {_e(f['title'])}</h3><div class="where">{_e(f['id'])} | {_e(f['source'])} | {_e(f['file'])}:{_e(f['line'])}</div><div class="grid"><div><b>Evidence</b><p>{_e(f['evidence'])}</p></div><div><b>Risk</b><p>{_e(f['risk'])}</p></div><div><b>Recommended change</b><p>{_e(f['recommendation'])}</p></div><div><b>Fix control</b><p>Patch: {str(f['patch_available']).lower()} | Auto-fix safe: {str(f['auto_fix_safe']).lower()} | Manual review: {str(f['manual_review_required']).lower()}</p></div></div>{patch}</article>"""

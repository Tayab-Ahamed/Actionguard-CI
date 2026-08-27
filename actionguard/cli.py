from pathlib import Path
import argparse
import json
from actionguard import __version__
from actionguard.scanner import audit
from actionguard.report import build_payload, write_html, write_json
from actionguard.email_sender import send_if_configured


def run_audit(args):
    repo = Path(args.path)
    result = audit(repo)
    payload = build_payload(repo, result.findings, result.scores, result.statuses)
    write_json(args.json, payload)
    write_html(args.html, payload)
    email = {"status": "not-requested"}
    if args.email:
        email = send_if_configured(repo.name, result.scores["overall"], payload["summary"], args.html)
    c = payload["summary"]
    print(
        f"ActionGuard score: {result.scores['overall']}/100 | critical {c['critical']} | high {c['high']} | medium {c['medium']}"
    )
    print(f"Reports: {args.html}, {args.json} | email: {email['status']}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="actionguard", description="Audit GitHub CI/CD, secrets, artifacts, dependencies, and agentic workflows."
    )
    p.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)
    for cmd in ["audit", "scan"]:
        a = sub.add_parser(cmd)
        a.add_argument("path", nargs="?", default=".")
        a.add_argument("--html", default="actionguard-report.html")
        a.add_argument("--json", default="actionguard-report.json")
        a.add_argument("--email", action="store_true")
        a.set_defaults(func=run_audit)
    r = sub.add_parser("report")
    r.add_argument("--json", required=True)
    r.add_argument("--html", required=True)

    def rerender(a):
        payload = json.loads(Path(a.json).read_text())
        write_html(a.html, payload)
        print(a.html)
        return 0

    r.set_defaults(func=rerender)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

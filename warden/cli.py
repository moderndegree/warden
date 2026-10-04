"""warden command line.

  warden scan     [TEXT | -f FILE | stdin] [-b prompt|content|outbound] [--no-lev] [--brief]
  warden redact   [TEXT | -f FILE | stdin] [--json]
  warden decide   -q QUESTION [-k yes_no|choice|score] [-o id=description ...] [-l level ...]
                  [-c CONTEXT] [ITEM ... | -f FILE (one item per line, or a JSON array)] [--brief]
  warden classify [TEXT | -f FILE | stdin] [--sensitivity] [--guard] [--brief]
  warden escalate -t TASK [TRIED | -f FILE | stdin] [--brief]
  warden route    [TEXT | -f FILE | stdin]            (experimental)
  warden eval     [--sets dev,feedback,gandalf,jailbreak,neuralchemy,pairs,safeguard,ipi,web] [--no-lev]
  warden health   [--brief]
  warden testbed  [--port 8740]

Exit codes (scan): 0 allow · 3 review · 4 block · 1 error · 2 usage. (redact): 0 nothing removed · 3 redacted.
(classify): 0 classified · 4 stopped by --guard · 1 lev unavailable. (escalate): 0 stay local · 3 escalate · 1 error.
"""
import argparse
import json
import sys

from . import __version__

EXIT = {"allow": 0, "review": 3, "block": 4}


def _text(args):
    """Input as text. Invalid UTF-8 never aborts a scan: bad bytes become U+FFFD and are scanned like the rest."""
    if getattr(args, "file", None):
        with open(args.file, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    if getattr(args, "text", None):
        return " ".join(args.text)
    if sys.stdin.isatty():
        raise SystemExit("warden: no input (pass TEXT, -f FILE, or pipe stdin)")
    return sys.stdin.buffer.read().decode("utf-8", errors="replace")


def _out(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")


def cmd_scan(args):
    from .guard import inspect
    r = inspect(_text(args), args.boundary, use_lev=not args.no_lev)
    if args.brief:
        top = ", ".join(f"{f['id']}({f['severity']})" for f in r["findings"][:4]) or "no findings"
        score = f" lev={r['score']:.2f}" if r["score"] is not None else ""
        extra = " DEGRADED: lev unavailable, rules only" if r["degraded"] else ""
        red = f" redacted={sum(r['redactions'].values())}" if r["redactions"] else ""
        print(f"{r['verdict']} → {r['action']}{score}{red} · {top}{extra}")
        if r["hidden_text"]:
            print(f"hidden text: {r['hidden_text']}")
    else:
        _out(r)
    return EXIT[r["verdict"]]


def cmd_redact(args):
    from .rules import redact, strip_invisible
    r = redact(strip_invisible(_text(args)))
    if args.json:
        _out(r)
    else:
        sys.stdout.write(r["text"])
        if r["counts"]:
            print("warden: redacted " + ", ".join(f"{n} {k}" for k, n in r["counts"].items()), file=sys.stderr)
    return 3 if r["counts"] else 0


def cmd_decide(args):
    from .decide import decide
    if args.file:
        raw = open(args.file, "rb").read().decode("utf-8", errors="replace")
        items = json.loads(raw) if raw.lstrip().startswith("[") else [l for l in raw.split("\n") if l.strip()]
    elif args.items:
        items = args.items
    elif not sys.stdin.isatty():
        items = [l for l in sys.stdin.buffer.read().decode("utf-8", errors="replace").split("\n") if l.strip()]
    else:
        raise SystemExit("warden decide: no items (pass ITEM ..., -f FILE, or pipe one item per line)")
    options = None
    if args.option:
        options = dict(o.split("=", 1) if "=" in o else (o, o) for o in args.option)
    r = decide(args.question, args.kind, items, options=options, levels=args.level, context=args.context)
    if args.brief:
        for x in r["results"]:
            print(f"{x['index']}\t{x['answer']}\t{x['p'] if 'p' in x else x['level']}")
        if not r["complete"]:
            print(f"incomplete: {r['error']}", file=sys.stderr)
    else:
        _out(r)
    return 0 if r["complete"] else 1


def cmd_classify(args):
    from .classify import brief, classify
    r = classify(_text(args), sensitivity=args.sensitivity, guard=args.guard)
    print(brief(r)) if args.brief else _out(r)
    return 4 if r["stopped"] else 1 if r["error"] else 0


def cmd_escalate(args):
    from .escalate import brief, escalate
    r = escalate(args.task, _text(args))
    print(brief(r)) if args.brief else _out(r)
    return 1 if r["error"] else 3 if r["escalate"] else 0


def cmd_route(args):
    from .router import route
    _out(route(_text(args)))
    return 0


def cmd_eval(args):
    from .evaluate import evaluate, summary
    def progress(name, i, n):
        if sys.stderr.isatty():
            print(f"\r{name}: {i}/{n}", end="", file=sys.stderr, flush=True)
    rep = evaluate([x.strip() for x in args.sets.split(",")], use_lev=not args.no_lev, progress=progress)
    if sys.stderr.isatty():
        print("\r", end="", file=sys.stderr)
    print(summary(rep))
    return 0


def cmd_health(args):
    from . import availability, config
    from .lev import Lev
    cfg = config.load("guard.json")
    up = Lev(cfg["decision_model"]).health()
    status = availability.check(force=True)
    if args.brief:
        print(f"lev {'up' if up else 'DOWN'} · " + " · ".join(f"{k} {'ok' if v['up'] else 'DOWN (' + v['why'] + ')'}"
                                                         for k, v in status.items() if k != "lev"))
    else:
        _out({"warden": __version__, "config_dir": str(config.config_dir()), "lev": cfg["decision_model"]["url"],
              "lev_up": up, "availability": status})
    return 0 if up else 1


def cmd_testbed(args):
    from .testbed.server import serve
    serve(args.host, args.port)
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="warden", description="Local guard and decision engine for AI agents.")
    ap.add_argument("--version", action="version", version=f"warden {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def text_args(p):
        p.add_argument("text", nargs="*", help="text (default: stdin)")
        p.add_argument("-f", "--file", help="read text from FILE")

    p = sub.add_parser("scan", help="inspect text at a boundary; exit 0 allow, 3 review, 4 block")
    text_args(p)
    p.add_argument("-b", "--boundary", choices=["prompt", "content", "outbound"], default="prompt")
    p.add_argument("--no-lev", action="store_true", help="rules only (no model call)")
    p.add_argument("--brief", action="store_true", help="one-line summary instead of JSON")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("redact", help="replace secrets and high-risk personal data; exit 3 if anything was removed")
    text_args(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_redact)

    p = sub.add_parser("decide", help="ask lev one question about each item")
    p.add_argument("items", nargs="*", help="items (default: -f FILE or stdin, one per line)")
    p.add_argument("-q", "--question", required=True)
    p.add_argument("-k", "--kind", choices=["yes_no", "choice", "score"], default="yes_no")
    p.add_argument("-o", "--option", action="append", help="choice option, id=description (repeat)")
    p.add_argument("-l", "--level", action="append", help="score level, lowest first (repeat)")
    p.add_argument("-c", "--context", help="short context shown with each item")
    p.add_argument("-f", "--file", help="items file: one per line, or a JSON array")
    p.add_argument("--brief", action="store_true", help="index<TAB>answer<TAB>p per line")
    p.set_defaults(fn=cmd_decide)

    p = sub.add_parser("classify", help="expert + mode (+ sensitivity) of a prompt; 2-3 lev calls")
    text_args(p)
    p.add_argument("--sensitivity", action="store_true", help="also score data sensitivity (+1 lev call)")
    p.add_argument("--guard", action="store_true", help="run the prompt guard first; stop on block (+2 lev calls)")
    p.add_argument("--brief", action="store_true", help="one-line summary instead of JSON")
    p.set_defaults(fn=cmd_classify)

    p = sub.add_parser("escalate", help="should a local agent hand this task to a frontier model? exit 3 = yes")
    p.add_argument("-t", "--task", required=True, help="the task the local agent was given")
    p.add_argument("text", nargs="*", help="short summary of what it tried (default: -f FILE or stdin)")
    p.add_argument("-f", "--file", help="read the summary from FILE")
    p.add_argument("--brief", action="store_true", help="one-line summary instead of JSON")
    p.set_defaults(fn=cmd_escalate)

    p = sub.add_parser("route", help="(experimental) pick agent + model for a prompt")
    text_args(p)
    p.set_defaults(fn=cmd_route)

    p = sub.add_parser("eval", help="measure the guard on dev, held-out, and feedback sets")
    p.add_argument("--sets", default="dev,feedback,gandalf,jailbreak,neuralchemy,pairs,safeguard,ipi,web")
    p.add_argument("--no-lev", action="store_true", help="rules only, as a baseline")
    p.set_defaults(fn=cmd_eval)

    p = sub.add_parser("health", help="check config, lev, and what routes can use (local checks only)")
    p.add_argument("--brief", action="store_true", help="one-line summary instead of JSON")
    p.set_defaults(fn=cmd_health)

    p = sub.add_parser("testbed", help="run the local test bed UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8740)
    p.set_defaults(fn=cmd_testbed)

    args = ap.parse_args(argv)
    # Text under inspection can hold lone surrogates or other unencodable characters; never crash on output.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    try:
        return args.fn(args)
    except (ValueError, OSError) as e:
        print(f"warden: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

import argparse, sys, json, os
from .scrub.pipeline import scrub_text

def main():
    ap = argparse.ArgumentParser(prog="secureprompt")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("scrub")
    s1.add_argument("input", help="path to a text file")
    s1.add_argument("--clevel", default=os.environ.get("C_LEVEL","C3"))
    args = ap.parse_args()

    if args.cmd == "scrub":
        text = open(args.input, "r", errors="ignore").read()
        result = scrub_text(text, c_level=args.clevel)
        print(json.dumps(result, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()

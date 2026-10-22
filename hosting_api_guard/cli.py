"""CLI: hosting-api-guard Module::function key=value ... [--apply]"""
import argparse, json, sys
from .guard import Guard, GuardConfig, GuardError
from .transport import panel_transport


def main(argv=None):
    ap = argparse.ArgumentParser(prog="hosting-api-guard")
    ap.add_argument("func")
    ap.add_argument("params", nargs="*", help="key=value")
    ap.add_argument("--config", required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--token-env", default="HAG_TOKEN")
    ap.add_argument("--auth-scheme", default="panel", help="scheme word in the Authorization header your host expects")
    ap.add_argument("--apply", action="store_true", help="actually perform writes (default: dry run)")
    a = ap.parse_args(argv)
    params = dict(p.split("=", 1) for p in a.params)
    cfg = GuardConfig.from_file(a.config, usernames=[a.user])
    g = Guard(panel_transport(a.base_url, a.user, a.token_env, auth_scheme=a.auth_scheme), cfg)
    try:
        print(json.dumps(g.call(a.func, params, apply=a.apply), indent=2))
        return 0
    except GuardError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

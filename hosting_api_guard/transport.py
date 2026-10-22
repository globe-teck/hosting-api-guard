"""Minimal HTTP transport for Module::function panel APIs (stdlib). Token is read from an env var name, never logged."""
import json, os, urllib.parse, urllib.request


def panel_transport(base_url, user, token_env="HAG_TOKEN", timeout=20, auth_scheme="panel"):
    def call(func, params):
        mod, fn = func.split("::", 1)
        url = "%s/execute/%s/%s?%s" % (base_url.rstrip("/"), mod, fn, urllib.parse.urlencode(params))
        req = urllib.request.Request(url, headers={"Authorization": "%s %s:%s" % (auth_scheme, user, os.environ.get(token_env, ""))})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    return call

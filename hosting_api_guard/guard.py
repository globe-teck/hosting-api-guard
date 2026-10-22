"""Core guard: policy checks around a transport that calls Module::function."""
import difflib, fnmatch, json, os, posixpath, threading, time

READ_PREFIXES = ("list", "get", "stat", "show", "fetch", "check", "read", "search")
SENSITIVE_NAMES = (".htaccess", ".htpasswd", ".env", "wp-config.php", "configuration.php",
                   "config.php", "settings.php", ".user.ini", "php.ini", "*.pem", "*.key", ".my.cnf")
CONTENT_READ_FUNCS = {"Fileman::get_file_content"}
CONTENT_WRITE_FUNCS = {"Fileman::save_file_content"}


class GuardError(Exception):
    pass


class Blocked(GuardError):
    pass


class RateLimited(GuardError):
    pass


class GuardConfig:
    def __init__(self, docroot="/home/example/public_html", allow=None, deny=None,
                 apply=False, rate_per_min=30, audit_path=None, usernames=(),
                 backup_hook=None, sensitive=SENSITIVE_NAMES):
        self.docroot = posixpath.normpath(docroot)
        self.allow = list(allow or ["*::list*", "*::get*", "Fileman::*", "StatsBar::*"])
        self.deny = list(deny or ["Passwd::*", "UserManager::*", "Ftp::passwd", "Mysql::set_password",
                                  "Tokens::*", "Backup::restore*", "Fileman::empty_trash"])
        self.apply = apply
        self.rate_per_min = rate_per_min
        self.audit_path = audit_path
        self.usernames = tuple(usernames)
        self.backup_hook = backup_hook
        self.sensitive = tuple(sensitive)

    @classmethod
    def from_file(cls, path, **over):
        with open(path) as f:
            d = json.load(f)
        d.update({k: v for k, v in over.items() if v is not None})
        return cls(**d)


def is_read(func):
    name = func.split("::", 1)[-1].lower()
    return name.startswith(READ_PREFIXES) or func in CONTENT_READ_FUNCS


class RateLimiter:
    def __init__(self, per_min, clock=time.monotonic):
        self.per_min, self.clock, self.hits, self.lock = per_min, clock, [], threading.Lock()

    def take(self):
        with self.lock:
            now = self.clock()
            self.hits = [t for t in self.hits if now - t < 60]
            if len(self.hits) >= self.per_min:
                raise RateLimited("rate limit: %d calls/min" % self.per_min)
            self.hits.append(now)


class Guard:
    """Wraps transport(func, params) -> dict. Never raises raw transport errors unredacted."""

    def __init__(self, transport, config=None, clock=time.monotonic):
        self.t = transport
        self.c = config or GuardConfig()
        self.rl = RateLimiter(self.c.rate_per_min, clock)

    # ---- policy -----------------------------------------------------
    def _r(self, s):
        from .redact import redact
        return redact(s, self.c.usernames)

    def check_function(self, func):
        if "::" not in func:
            raise Blocked("function must be Module::function")
        if any(fnmatch.fnmatchcase(func, p) for p in self.c.deny):
            raise Blocked("denied by deny list: " + func)
        if not any(fnmatch.fnmatchcase(func, p) for p in self.c.allow):
            raise Blocked("not on allow list: " + func)

    def check_path(self, path, content_read=False):
        if not path:
            return None
        p = path if path.startswith("/") else posixpath.join(self.c.docroot, path)
        p = posixpath.normpath(p)
        if p != self.c.docroot and not p.startswith(self.c.docroot + "/"):
            raise Blocked("path outside docroot")
        base = posixpath.basename(p)
        if content_read and any(fnmatch.fnmatch(base, pat) for pat in self.c.sensitive):
            raise Blocked("refusing to echo sensitive file: " + base)
        return p

    def _paths(self, params):
        out = []
        d = params.get("dir")
        f = params.get("file")
        if d is not None or f is not None:
            out.append(posixpath.join(d or self.c.docroot, f or ""))
        for k in ("path", "sourcefiles", "destfiles"):
            if params.get(k):
                out.extend(str(params[k]).split(","))
        return out

    # ---- audit ------------------------------------------------------
    def audit(self, **ev):
        ev["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        line = self._r(json.dumps(ev, sort_keys=True))
        if self.c.audit_path:
            with open(self.c.audit_path, "a") as f:
                f.write(line + "\n")
        return line

    # ---- call -------------------------------------------------------
    def call(self, func, params=None, apply=None):
        params = dict(params or {})
        apply = self.c.apply if apply is None else apply
        read = is_read(func)
        try:
            self.check_function(func)
            for p in self._paths(params):
                self.check_path(p, content_read=func in CONTENT_READ_FUNCS)
            self.rl.take()
        except GuardError as e:
            self.audit(func=func, decision="blocked", reason=str(e))
            raise type(e)(self._r(e))
        safe_params = {k: ("<%d bytes>" % len(v) if k == "content" else v) for k, v in params.items()}
        if read:
            res = self._send(func, params)
            self.audit(func=func, decision="read", params=safe_params)
            return res
        preview = self.preview(func, params)
        if not apply:
            self.audit(func=func, decision="dry-run", params=safe_params)
            return {"dry_run": True, "func": func, "preview": preview}
        if self.c.backup_hook is None:
            self.audit(func=func, decision="blocked", reason="no backup hook")
            raise Blocked("write refused: no backup-before-write hook configured")
        try:
            ref = self.c.backup_hook(func, params, self)
        except Exception as e:
            self.audit(func=func, decision="blocked", reason="backup failed")
            raise Blocked(self._r("write refused: backup failed: %s" % e))
        if not ref:
            self.audit(func=func, decision="blocked", reason="backup returned nothing")
            raise Blocked("write refused: backup hook returned no reference")
        res = self._send(func, params)
        self.audit(func=func, decision="applied", params=safe_params, backup=str(ref))
        return {"dry_run": False, "func": func, "backup": ref, "result": res}

    def _send(self, func, params):
        try:
            return self.t(func, params)
        except Exception as e:
            raise GuardError(self._r("transport error: %s" % e)) from None

    def preview(self, func, params):
        if func in CONTENT_WRITE_FUNCS:
            path = posixpath.join(params.get("dir", self.c.docroot), params.get("file", ""))
            try:
                old = self.t("Fileman::get_file_content", {"dir": params.get("dir"), "file": params.get("file")})
                old = (old.get("data") or {}).get("content", "")
            except Exception:
                old = ""
            diff = difflib.unified_diff(old.splitlines(True), params.get("content", "").splitlines(True),
                                        "a" + path, "b" + path)
            return self._r("".join(diff))
        return self._r("%s %s" % (func, json.dumps({k: v for k, v in params.items() if k != "content"}, sort_keys=True)))

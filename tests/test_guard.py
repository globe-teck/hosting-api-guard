import json, os, tempfile, unittest
from hosting_api_guard import Guard, GuardConfig, Blocked, RateLimited, GuardError, redact
from hosting_api_guard.guard import is_read
from hosting_api_guard.mock import MockPanel, serve, FAKE_TOKEN, USER
from hosting_api_guard.transport import uapi_transport
from hosting_api_guard import cli

ROOT = "/home/%s/public_html" % USER


def mk(**kw):
    p = MockPanel()
    kw.setdefault("docroot", ROOT)
    kw.setdefault("usernames", [USER])
    return p, Guard(p, GuardConfig(**kw))


class Lists(unittest.TestCase):
    def test_allow_read(self):
        p, g = mk()
        self.assertEqual(g.call("DomainInfo::list_domains")["data"]["main_domain"], "example.com")
    def test_not_allowed(self):
        p, g = mk()
        with self.assertRaises(Blocked): g.call("Email::add_pop", {"email": "a"})
        self.assertEqual(p.calls, [])
    def test_deny_beats_allow(self):
        p, g = mk(allow=["*::*"])
        with self.assertRaises(Blocked): g.call("Passwd::change_password")
    def test_deny_tokens(self):
        p, g = mk(allow=["*::*"])
        with self.assertRaises(Blocked): g.call("Tokens::list")
    def test_bad_name(self):
        p, g = mk()
        with self.assertRaises(Blocked): g.call("list_domains")
    def test_custom_allow(self):
        p, g = mk(allow=["Foo::bar"], deny=[])
        self.assertEqual(g.call("Foo::bar", apply=False)["dry_run"], True)
    def test_is_read(self):
        self.assertTrue(is_read("Fileman::list_files"))
        self.assertTrue(is_read("Fileman::get_file_content"))
        self.assertFalse(is_read("Fileman::save_file_content"))
        self.assertFalse(is_read("Mysql::create_database"))


class ReadOnlyDryRun(unittest.TestCase):
    def test_write_default_dry_run(self):
        p, g = mk()
        r = g.call("Fileman::save_file_content", {"dir": ROOT, "file": "index.html", "content": "<h1>new</h1>\n"})
        self.assertTrue(r["dry_run"])
        self.assertIn("-<h1>example.com</h1>", r["preview"])
        self.assertIn("+<h1>new</h1>", r["preview"])
        self.assertNotIn("Fileman::save_file_content", p.calls)
        self.assertEqual(p.files[ROOT + "/index.html"], "<h1>example.com</h1>\n")
    def test_new_file_diff(self):
        p, g = mk()
        r = g.call("Fileman::save_file_content", {"dir": ROOT, "file": "new.html", "content": "x\n"})
        self.assertIn("+x", r["preview"])
    def test_generic_preview(self):
        p, g = mk(allow=["Mysql::*"])
        r = g.call("Mysql::create_database", {"name": "exampledb"})
        self.assertIn("exampledb", r["preview"])
    def test_apply_without_backup_refused(self):
        p, g = mk()
        with self.assertRaises(Blocked):
            g.call("Fileman::save_file_content", {"dir": ROOT, "file": "index.html", "content": "x"}, apply=True)
        self.assertNotIn("Fileman::save_file_content", p.calls)
    def test_config_apply_flag(self):
        p, g = mk(apply=True, backup_hook=lambda f, pa, g: "bk-1")
        self.assertFalse(g.call("Fileman::save_file_content", {"dir": ROOT, "file": "a.txt", "content": "x"})["dry_run"])


class Backup(unittest.TestCase):
    def test_backup_then_write(self):
        order = []
        p = MockPanel()
        def hook(func, params, guard):
            order.append("backup"); return "bk-123"
        orig = p.__call__
        g = Guard(lambda f, pa: (order.append(f), orig(f, pa))[1], GuardConfig(docroot=ROOT, backup_hook=hook))
        r = g.call("Fileman::save_file_content", {"dir": ROOT, "file": "index.html", "content": "new"}, apply=True)
        self.assertEqual(r["backup"], "bk-123")
        self.assertLess(order.index("backup"), order.index("Fileman::save_file_content"))
        self.assertEqual(p.files[ROOT + "/index.html"], "new")
    def test_backup_failure_blocks(self):
        def hook(*a): raise IOError("disk full token=%s" % FAKE_TOKEN)
        p, g = mk(backup_hook=hook)
        with self.assertRaises(Blocked) as cm:
            g.call("Fileman::save_file_content", {"dir": ROOT, "file": "a", "content": "x"}, apply=True)
        self.assertNotIn(FAKE_TOKEN, str(cm.exception))
        self.assertNotIn("Fileman::save_file_content", p.calls)
    def test_backup_empty_ref_blocks(self):
        p, g = mk(backup_hook=lambda *a: "")
        with self.assertRaises(Blocked):
            g.call("Fileman::save_file_content", {"dir": ROOT, "file": "a", "content": "x"}, apply=True)


class Paths(unittest.TestCase):
    def test_outside_docroot(self):
        p, g = mk()
        with self.assertRaises(Blocked): g.call("Fileman::get_file_content", {"dir": "/etc", "file": "passwd"})
    def test_traversal(self):
        p, g = mk()
        with self.assertRaises(Blocked): g.call("Fileman::get_file_content", {"dir": ROOT + "/../", "file": ".bashrc"})
    def test_prefix_trick(self):
        p, g = mk()
        with self.assertRaises(Blocked): g.call("Fileman::list_files", {"dir": ROOT + "_evil"})
    def test_relative_ok(self):
        p, g = mk()
        self.assertEqual(g.call("Fileman::get_file_content", {"dir": "", "file": "index.html"})["status"], 1)
    def test_htaccess_read_refused(self):
        p, g = mk()
        with self.assertRaises(Blocked): g.call("Fileman::get_file_content", {"dir": ROOT, "file": ".htaccess"})
        self.assertEqual(p.calls, [])
    def test_wpconfig_read_refused(self):
        p, g = mk()
        with self.assertRaises(Blocked): g.call("Fileman::get_file_content", {"dir": ROOT, "file": "wp-config.php"})
    def test_key_glob(self):
        p, g = mk()
        with self.assertRaises(Blocked): g.call("Fileman::get_file_content", {"dir": ROOT, "file": "site.key"})
    def test_list_with_sensitive_dir_ok(self):
        p, g = mk()
        self.assertEqual(g.call("Fileman::list_files", {"dir": ROOT})["status"], 1)
    def test_path_param_list(self):
        p, g = mk(allow=["Fileman::*"])
        with self.assertRaises(Blocked):
            g.call("Fileman::copy_files", {"sourcefiles": ROOT + "/a,/etc/shadow"})


class Redaction(unittest.TestCase):
    def test_token_kv(self):
        self.assertNotIn("abc123", redact("token=abc123 x"))
    def test_auth_header(self):
        s = redact("Authorization: cpanel %s:%s" % (USER, FAKE_TOKEN), [USER])
        self.assertNotIn(FAKE_TOKEN, s); self.assertNotIn(USER, s)
    def test_bare_token(self):
        self.assertNotIn(FAKE_TOKEN, redact("x %s y" % FAKE_TOKEN))
    def test_username(self):
        self.assertEqual(redact("/home/exampleuser/x", ["exampleuser"]), "/home/[USER]/x")
    def test_url_creds(self):
        self.assertNotIn("pw", redact("https://u:pw@example.com/"))  # pragma: allowlist secret
    def test_func_name_kept(self):
        self.assertEqual(redact("Passwd::change_password"), "Passwd::change_password")
    def test_json_password(self):
        self.assertNotIn("hunter2", redact('{"password": "hunter2"}'))  # pragma: allowlist secret
    def test_transport_error_redacted(self):
        p, g = mk(allow=["Boom::*"])
        with self.assertRaises(GuardError) as cm: g.call("Boom::fetch")
        self.assertNotIn(FAKE_TOKEN, str(cm.exception)); self.assertNotIn(USER, str(cm.exception))
    def test_blocked_msg_redacted(self):
        p, g = mk()
        with self.assertRaises(Blocked) as cm:
            g.call("Fileman::get_file_content", {"dir": "/home/%s/tmp" % USER, "file": "x"})
        self.assertNotIn(USER, str(cm.exception))


class Rate(unittest.TestCase):
    def test_limit(self):
        t = [0.0]
        p = MockPanel()
        g = Guard(p, GuardConfig(docroot=ROOT, rate_per_min=3), clock=lambda: t[0])
        for _ in range(3): g.call("DomainInfo::list_domains")
        with self.assertRaises(RateLimited): g.call("DomainInfo::list_domains")
        t[0] = 61
        g.call("DomainInfo::list_domains")
    def test_blocked_not_counted(self):
        p = MockPanel()
        g = Guard(p, GuardConfig(docroot=ROOT, rate_per_min=1))
        with self.assertRaises(Blocked): g.call("Passwd::x")
        g.call("DomainInfo::list_domains")


class Audit(unittest.TestCase):
    def test_audit_lines(self):
        with tempfile.TemporaryDirectory() as d:
            ap = os.path.join(d, "audit.jsonl")
            p, g = mk(audit_path=ap)
            g.call("DomainInfo::list_domains")
            g.call("Fileman::save_file_content", {"dir": ROOT, "file": "a", "content": "secretbody"})
            try: g.call("Passwd::change_password", {"password": "hunter2"})
            except Blocked: pass
            lines = [json.loads(l) for l in open(ap)]
            self.assertEqual([l["decision"] for l in lines], ["read", "dry-run", "blocked"])
            raw = open(ap).read()
            self.assertNotIn("secretbody", raw); self.assertNotIn(USER, raw); self.assertNotIn("hunter2", raw)
    def test_applied_has_backup(self):
        with tempfile.TemporaryDirectory() as d:
            ap = os.path.join(d, "a.jsonl")
            p, g = mk(audit_path=ap, backup_hook=lambda *a: "bk-9")
            g.call("Fileman::save_file_content", {"dir": ROOT, "file": "a", "content": "x"}, apply=True)
            self.assertEqual(json.loads(open(ap).read())["backup"], "bk-9")


class Http(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.panel = MockPanel(); cls.srv = serve(cls.panel)
        cls.url = "http://127.0.0.1:%d" % cls.srv.server_port
        os.environ["HAG_TEST_TOKEN"] = FAKE_TOKEN
    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
    def test_http_read(self):
        g = Guard(uapi_transport(self.url, USER, "HAG_TEST_TOKEN"), GuardConfig(docroot=ROOT, usernames=[USER]))
        self.assertEqual(g.call("DomainInfo::list_domains")["data"]["main_domain"], "example.com")
    def test_http_bad_token_redacted(self):
        g = Guard(uapi_transport(self.url, USER, "HAG_NO_SUCH"), GuardConfig(docroot=ROOT, usernames=[USER]))
        with self.assertRaises(GuardError) as cm: g.call("DomainInfo::list_domains")
        self.assertIn("401", str(cm.exception))
    def _cfg(self, d):
        c = os.path.join(d, "c.json")
        with open(c, "w") as fh: json.dump({"docroot": ROOT}, fh)
        return ["--config", c, "--base-url", self.url, "--user", USER, "--token-env", "HAG_TEST_TOKEN"]
    def test_cli_dry_run_default(self):
        with tempfile.TemporaryDirectory() as d:
            rc = cli.main(["Fileman::save_file_content", "dir=" + ROOT, "file=index.html", "content=hi"] + self._cfg(d))
            self.assertEqual(rc, 0)
            self.assertNotEqual(self.panel.files[ROOT + "/index.html"], "hi")
    def test_cli_apply_needs_backup(self):
        with tempfile.TemporaryDirectory() as d:
            rc = cli.main(["Fileman::save_file_content", "dir=" + ROOT, "file=index.html", "content=hi", "--apply"] + self._cfg(d))
            self.assertEqual(rc, 2)
    def test_cli_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(cli.main(["Passwd::change_password"] + self._cfg(d)), 2)


if __name__ == "__main__":
    unittest.main()

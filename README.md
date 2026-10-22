# hosting-api-guard

A stdlib-only Python safety layer for AI agents that call hosting control-panel APIs (cPanel UAPI-style `Module::function`).

Install: `git clone https://github.com/globe-teck/hosting-api-guard && cd hosting-api-guard && pip install .` (stdlib only, Python 3.8+; or run in place with no install).

- **Allow/deny lists** of API functions (fnmatch globs). The deny list wins.
- **Read-only by default.** Writes are dry runs unless you pass `--apply` (or `apply=True`).
- **Diff preview** for file writes in dry-run mode.
- **Backup before every write.** If no backup hook is set, the hook fails, or it returns no reference, the write is refused.
- **Path guards.** Paths outside the docroot (including `..` and prefix tricks) are blocked. It won't echo `.htaccess`, `wp-config.php`, `.env`, `*.key` and similar files.
- **Redaction** of tokens, auth headers, URL credentials and usernames in errors and audit lines.
- **Rate limiting** (sliding window, calls/min).
- **JSONL audit log** recording read / dry-run / blocked / applied, plus the backup ref. File contents are logged only as byte counts.

```bash
python3 -m hosting_api_guard.cli DomainInfo::list_domains \
  --config examples/config.json --base-url https://panel.example.com:2083 --user exampleuser
# write: dry run with diff; add --apply to perform (needs a backup hook via the Python API)
```

```python
from hosting_api_guard import Guard, GuardConfig
g = Guard(transport, GuardConfig(docroot="/home/exampleuser/public_html",
          backup_hook=lambda func, params, guard: make_backup(params), usernames=["exampleuser"]))
g.call("Fileman::save_file_content", {"dir": "...", "file": "index.html", "content": "..."})  # dry run
```

The token is read from an env var (default `HAG_TOKEN`) and never printed.

42 offline tests run fully offline against a built-in mock panel (example.com, fake token): `python3 -m unittest discover -s tests -t .`

## License

MIT. See [LICENSE](LICENSE). Copyright (c) 2026 Globe Teck.

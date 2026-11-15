import io, json, os, tempfile, unittest, contextlib
import _path  # noqa
from secretscan.cli import main
from secretscan.scanner import scan_text, scan_paths, redact
from secretscan.rules import shannon_entropy, looks_like_placeholder

def run(argv):
    o, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        try: c = main(argv)
        except SystemExit as x: c = x.code
    return c, o.getvalue(), e.getvalue()

# Fake, syntactically-shaped test values assembled at runtime so this file does not itself contain real-looking secrets.
AWS = "AKIA" + "QWERTYUIOPASDFGH"
GH = "ghp_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jL5"
PK = "-----BEGIN " + "RSA PRIVATE KEY-----"

class T(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory(); self.addCleanup(t.cleanup); self.d = t.name
    def w(self, name, data):
        p = os.path.join(self.d, name); os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh: fh.write(data if isinstance(data, bytes) else data.encode())
        return p

    def test_detects_known_formats(self):
        for text, rid in [(f"key={AWS}", "aws-access-key-id"), (f"t = '{GH}'", "github-token"), (PK, "private-key-block")]:
            self.assertIn(rid, [f.rule_id for f in scan_text(text)], rid)
    def test_url_credentials(self):
        f = scan_text("db = postgres://admin:Sup3rS3cretPw@db.internal:5432/app")  # secretscan:ignore (fake fixture)
        self.assertEqual(f[0].rule_id, "url-credentials")
    def test_generic_assignment_entropy(self):
        self.assertTrue(scan_text('password = "k8Jd92xLq0Zp"'))  # secretscan:ignore (fake fixture)
        self.assertFalse(scan_text('password = "aaaaaaaaaaaa"'))
    def test_placeholders_ignored_unless_requested(self):
        line = 'api_key = "your-api-key-here-1234"'
        self.assertFalse(scan_text(line)); self.assertTrue(scan_text(line, allow_placeholders=True))
    def test_ignore_marker(self):
        self.assertFalse(scan_text(f"x={AWS}  # secretscan:ignore"))
    def test_redaction_never_leaks_full_value(self):
        f = scan_text(f"x={GH}")[0]; self.assertNotIn(GH, f.preview); self.assertEqual(redact("abc"), "***")
    def test_clean_file_exit_0_and_findings_exit_1(self):
        self.w("ok.py", "print('hello')\n"); self.assertEqual(run(["scan", self.d])[0], 0)
        self.w("bad.py", f"K='{AWS}'\n"); c, o, _ = run(["scan", self.d]); self.assertEqual(c, 1); self.assertIn("bad.py:1", o)
        self.assertNotIn(AWS, o)
    def test_empty_file_and_dir(self):
        self.w("empty.txt", ""); self.assertEqual(run(["scan", self.d])[0], 0)
    def test_missing_path(self):
        c, _, e = run(["scan", os.path.join(self.d, "nope")]); self.assertEqual(c, 2)
    def test_binary_and_excluded_dirs(self):
        self.w("b.dat", b"\x00\x01" + AWS.encode()); self.w("node_modules/x.js", f"k='{AWS}'")
        self.assertEqual(run(["scan", self.d])[0], 0)
    def test_json_output_and_severity_filter(self):
        self.w("a.txt", f"k={AWS}\ntok=AIza" + "A" * 35 + "\n")
        j = json.loads(run(["scan", self.d, "--format", "json", "--min-severity", "high"])[1])
        self.assertEqual({f["rule_id"] for f in j["findings"]}, {"aws-access-key-id"})
    def test_large_file_skipped_with_warning(self):
        self.w("big.txt", b"a" * (2 * 1024 * 1024 + 10))
        f, errs, n = scan_paths([self.d]); self.assertTrue(any("skipped" in e for e in errs))
    def test_rules_command(self):
        c, o, _ = run(["rules"]); self.assertEqual(c, 0); self.assertIn("aws-access-key-id", o)
    def test_unreadable(self):
        if os.geteuid() == 0: self.skipTest("root bypasses permissions")
        p = self.w("x.txt", "a"); os.chmod(p, 0)
        _, errs, _ = scan_paths([self.d]); os.chmod(p, 0o644); self.assertTrue(errs)
    def test_helpers(self):
        self.assertGreater(shannon_entropy("abcdefgh"), 2.9); self.assertTrue(looks_like_placeholder("YOUR_KEY"))
    def test_invalid_utf8_does_not_crash(self):
        self.w("l.txt", b"\xff\xfe\xfa" + f"k={AWS}".encode()); self.assertEqual(run(["scan", self.d])[0], 1)

    def test_broken_pipe_is_quiet(self):
        """Closing the reader early (like `| head`) must not print a traceback."""
        import subprocess, sys as _s
        env = {**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")}
        pr = subprocess.Popen([_s.executable, "-m", "secretscan"] + ["rules"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        pr.stdout.close(); err = pr.stderr.read(); pr.stderr.close(); pr.wait()
        self.assertNotIn(b"Traceback", err); self.assertEqual(pr.returncode, 0)

if __name__ == "__main__": unittest.main()

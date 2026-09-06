import hashlib
import importlib.util
import pathlib
import stat
import sys
import tempfile
import textwrap
import unittest

P = pathlib.Path(__file__).parents[1] / "certwatch.py"
S = importlib.util.spec_from_file_location("certwatch_c", P)
c = importlib.util.module_from_spec(S)
sys.modules[S.name] = c
S.loader.exec_module(c)

BASE = b"""subject=CN=example.com,O=Example
issuer=CN=Issuer
serial=01ab
notBefore=Jan  1 00:00:00 2026 GMT
notAfter=Feb  1 00:00:00 2026 GMT
"""

# Public example.com leaf decoder output captured during the 2026-09-05
# Ubuntu 24.04.1 WSL2 validation with OpenSSL 3.0.13. The adjacent byte
# literals make the significant trailing space on the SAN heading visible.
OPENSSL_3_0_13_EXAMPLE_COM = (
    b"subject=CN=example.com\n"
    b"issuer=CN=Cloudflare TLS Issuing ECC CA 3,O=SSL Corporation,C=US\n"
    b"serial=0624D0AB311558780B7D5213B9631831\n"
    b"notBefore=Jul 29 22:10:08 2026 GMT\n"
    b"notAfter=Oct 27 22:17:21 2026 GMT\n"
    b"X509v3 Subject Alternative Name:" b" \n"
    b"    DNS:example.com, DNS:*.example.com\n"
)


class CertificateTests(unittest.TestCase):
    def fake_decoder(self, body: str) -> str:
        directory = tempfile.mkdtemp()
        path = pathlib.Path(directory) / "openssl"
        path.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(body))
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        self.addCleanup(lambda: __import__("shutil").rmtree(directory))
        return str(path)

    def test_fingerprint(self):
        expected = ":".join(f"{x:02X}" for x in hashlib.sha256(b"abc").digest())
        self.assertEqual(c.fingerprint(b"abc"), expected)

    def test_fields(self):
        result = c.parse_certificate_output(BASE, b"abc")
        self.assertEqual(
            (result.subject, result.issuer, result.serial, result.sans),
            ("CN=example.com,O=Example", "CN=Issuer", "01AB", ()),
        )

    def test_empty_subject_with_critical_san(self):
        raw = BASE.replace(b"subject=CN=example.com,O=Example", b"subject=")
        raw += b"X509v3 Subject Alternative Name: critical\n    DNS:example.com\n"
        result = c.parse_certificate_output(raw, b"x")
        self.assertEqual(result.subject, "")
        self.assertEqual(result.sans, (("DNS", "example.com"),))

    def test_san_heading_horizontal_ascii_whitespace_variants(self):
        headings = (
            b"X509v3 Subject Alternative Name:",
            b"X509v3 Subject Alternative Name: ",
            b"X509v3 Subject Alternative Name: critical",
            b"X509v3 Subject Alternative Name: critical ",
            b"X509v3 Subject Alternative Name:\t",
            b"X509v3 Subject Alternative Name: critical\t",
        )
        for heading in headings:
            with self.subTest(heading=heading):
                raw = BASE + heading + b"\n    DNS:example.com, DNS:www.example.com\n"
                result = c.parse_certificate_output(raw, b"x")
                self.assertEqual(
                    result.sans,
                    (("DNS", "example.com"), ("DNS", "www.example.com")),
                )

    def test_captured_openssl_3_0_13_san_heading(self):
        self.assertIn(
            b"X509v3 Subject Alternative Name: \n", OPENSSL_3_0_13_EXAMPLE_COM
        )
        result = c.parse_certificate_output(
            OPENSSL_3_0_13_EXAMPLE_COM, b"public-example-leaf"
        )
        self.assertEqual(
            result.sans,
            (("DNS", "*.example.com"), ("DNS", "example.com")),
        )

    def test_san_heading_rejects_unsupported_suffix_and_unicode_whitespace(self):
        headings = (
            b"X509v3 Subject Alternative Name: critical extra",
            b"X509v3 Subject Alternative Name:\v",
            "X509v3 Subject Alternative Name:\N{NO-BREAK SPACE}".encode("utf-8"),
        )
        for heading in headings:
            with self.subTest(heading=heading), self.assertRaisesRegex(
                c.CertWatchError, "malformed"
            ):
                c.parse_certificate_output(BASE + heading + b"\n    DNS:example.com\n", b"x")

    def test_all_sans_order_and_dedupe(self):
        raw = BASE + (
            b"X509v3 Subject Alternative Name:\n"
            b"    DNS:z.test, DNS:a.test, IP Address:192.0.2.01, URI:https://x.test/a, email:a@x.test, DNS:a.test\n"
        )
        with self.assertRaisesRegex(c.CertWatchError, "malformed"):
            c.parse_certificate_output(raw, b"x")
        raw = raw.replace(b"192.0.2.01", b"2001:0db8::1")
        result = c.parse_certificate_output(raw, b"x")
        self.assertIn(("IP", "2001:db8::1"), result.sans)
        self.assertEqual(len(result.sans), 5)

    def test_malformed_forms(self):
        cases = [
            b"",
            BASE + b"serial=AA\n",
            BASE.replace(b"notAfter=", b"end="),
            BASE.replace(b"GMT", b"UTC", 1),
            BASE + b"junk\n",
            BASE.replace(b"serial=01ab", b"serial=no"),
            BASE + b"\0",
            BASE + b"X509v3 Subject Alternative Name: maybe\n    DNS:x\n",
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(c.CertWatchError):
                c.parse_certificate_output(raw, b"x")

    def test_invalid_utf8(self):
        with self.assertRaises(c.CertWatchError):
            c.parse_certificate_output(b"\xff", b"x")

    def test_end_before_start(self):
        raw = BASE.replace(
            b"notAfter=Feb  1 00:00:00 2026 GMT",
            b"notAfter=Dec  1 00:00:00 2025 GMT",
        )
        with self.assertRaises(c.CertWatchError):
            c.parse_certificate_output(raw, b"x")

    def test_malformed_san(self):
        with self.assertRaises(c.CertWatchError):
            c.parse_certificate_output(
                BASE + b"X509v3 Subject Alternative Name:\n  other:thing\n",
                b"x",
            )

    def test_find_decoder(self):
        self.assertEqual(c.find_decoder(lambda _: "/usr/bin/openssl"), "/usr/bin/openssl")
        with self.assertRaisesRegex(c.CertWatchError, "not available"):
            c.find_decoder(lambda _: None)

    def test_sanitize(self):
        value = "a\\b\n\r\t\0\x1b\u202e\u2066\u200b\u2028\u2029"
        safe = c.sanitize(value)
        self.assertNotIn("\x1b", safe)
        self.assertNotIn("\n", safe)
        self.assertIn("\\x0A", safe)
        self.assertIn("\\u202E", safe)
        self.assertIn("\\x5C", safe)

    def test_openssl_arguments(self):
        self.assertEqual(c.OPENSSL_ARGS[0], "x509")
        self.assertIn("RFC2253", c.OPENSSL_ARGS)
        self.assertNotIn("s_client", c.OPENSSL_ARGS)

    def test_decoder_round_trip_and_environment(self):
        path = self.fake_decoder(
            """
            import os, sys
            data = sys.stdin.buffer.read()
            if data != b'DER':
                sys.exit(9)
            if os.environ.get('LC_ALL') != 'C' or os.environ.get('LANG') != 'C':
                sys.exit(8)
            sys.stdout.buffer.write(b'OK')
            """
        )
        self.assertEqual(c.run_decoder(path, b"DER"), b"OK")

    def test_decoder_nonzero(self):
        path = self.fake_decoder("import sys\nsys.exit(7)\n")
        with self.assertRaisesRegex(c.CertWatchError, "decoder failed"):
            c.run_decoder(path, b"DER")

    def test_decoder_timeout_covers_input_and_process_lifetime(self):
        path = self.fake_decoder("import time\ntime.sleep(2)\n")
        old = c.DECODER_TIMEOUT
        c.DECODER_TIMEOUT = 0.1
        self.addCleanup(setattr, c, "DECODER_TIMEOUT", old)
        with self.assertRaisesRegex(c.CertWatchError, "timed out"):
            c.run_decoder(path, b"x" * c.MAX_CERTIFICATE_BYTES)

    def test_decoder_stdout_overflow(self):
        path = self.fake_decoder(
            f"import sys\nsys.stdin.buffer.read()\nsys.stdout.buffer.write(b'x' * {c.MAX_DECODER_OUTPUT + 1})\n"
        )
        with self.assertRaisesRegex(c.CertWatchError, "oversized"):
            c.run_decoder(path, b"DER")

    def test_decoder_stderr_overflow(self):
        path = self.fake_decoder(
            f"import sys\nsys.stdin.buffer.read()\nsys.stderr.buffer.write(b'x' * {c.MAX_DECODER_OUTPUT + 1})\n"
        )
        with self.assertRaisesRegex(c.CertWatchError, "oversized"):
            c.run_decoder(path, b"DER")

    def test_decoder_empty_stdout(self):
        path = self.fake_decoder("import sys\nsys.stdin.buffer.read()\n")
        with self.assertRaisesRegex(c.CertWatchError, "malformed"):
            c.run_decoder(path, b"DER")


if __name__ == "__main__":
    unittest.main()

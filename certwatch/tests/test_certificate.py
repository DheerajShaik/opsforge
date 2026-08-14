import hashlib,importlib.util,pathlib,unittest
from unittest import mock
P=pathlib.Path(__file__).parents[1]/'certwatch.py'; S=importlib.util.spec_from_file_location('certwatch_c',P); c=importlib.util.module_from_spec(S); import sys; sys.modules[S.name]=c; S.loader.exec_module(c)
BASE=b'''subject=CN=example.com,O=Example\nissuer=CN=Issuer\nserial=01ab\nnotBefore=Jan  1 00:00:00 2026 GMT\nnotAfter=Feb  1 00:00:00 2026 GMT\n'''
class CertificateTests(unittest.TestCase):
 def test_fingerprint(self): self.assertEqual(c.fingerprint(b'abc'),':'.join(f'{x:02X}' for x in hashlib.sha256(b'abc').digest()))
 def test_fields(self):
  x=c.parse_certificate_output(BASE,b'abc'); self.assertEqual((x.subject,x.issuer,x.serial,x.sans),('CN=example.com,O=Example','CN=Issuer','01AB',()))
 def test_all_sans_order_and_dedupe(self):
  raw=BASE+b'X509v3 Subject Alternative Name:\n    DNS:z.test, DNS:a.test, IP Address:192.0.2.01, URI:https://x.test/a, email:a@x.test, DNS:a.test\n'
  # Leading-zero IPv4 is deliberately malformed.
  with self.assertRaisesRegex(c.CertWatchError,'malformed'): c.parse_certificate_output(raw,b'x')
  raw=raw.replace(b'192.0.2.01',b'2001:0db8::1')
  x=c.parse_certificate_output(raw,b'x'); self.assertIn(('IP','2001:db8::1'),x.sans); self.assertEqual(len(x.sans),5)
 def test_malformed_forms(self):
  cases=[b'',BASE+b'serial=AA\n',BASE.replace(b'notAfter=',b'end='),BASE.replace(b'GMT',b'UTC',1),BASE+b'junk\n',BASE.replace(b'serial=01ab',b'serial=no'),BASE+b'\0']
  for raw in cases:
   with self.subTest(raw=raw),self.assertRaises(c.CertWatchError): c.parse_certificate_output(raw,b'x')
 def test_invalid_utf8(self):
  with self.assertRaises(c.CertWatchError): c.parse_certificate_output(b'\xff',b'x')
 def test_end_before_start(self):
  raw=BASE.replace(b'notAfter=Feb  1 00:00:00 2026 GMT', b'notAfter=Dec  1 00:00:00 2025 GMT')
  with self.assertRaises(c.CertWatchError): c.parse_certificate_output(raw,b'x')
 def test_malformed_san(self):
  with self.assertRaises(c.CertWatchError): c.parse_certificate_output(BASE+b'X509v3 Subject Alternative Name:\n  other:thing\n',b'x')
 def test_find_decoder(self):
  self.assertEqual(c.find_decoder(lambda _: '/usr/bin/openssl'),'/usr/bin/openssl')
  with self.assertRaisesRegex(c.CertWatchError,"not available"): c.find_decoder(lambda _: None)
 def test_sanitize(self):
  value='a\\b\n\r\t\0\x1b\u202e\u2066\u200b\u2028\u2029'
  safe=c.sanitize(value); self.assertNotIn('\x1b',safe); self.assertNotIn('\n',safe); self.assertIn('\\x0A',safe); self.assertIn('\\u202E',safe); self.assertIn('\\x5C',safe)
 def test_openssl_arguments(self): self.assertEqual(c.OPENSSL_ARGS[0],'x509'); self.assertIn('RFC2253',c.OPENSSL_ARGS); self.assertNotIn('s_client',c.OPENSSL_ARGS)

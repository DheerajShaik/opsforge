import importlib.util, pathlib, unittest
P=pathlib.Path(__file__).parents[1]/'certwatch.py'; S=importlib.util.spec_from_file_location('certwatch',P); c=importlib.util.module_from_spec(S); import sys; sys.modules[S.name]=c; S.loader.exec_module(c)

class TargetTests(unittest.TestCase):
 def ok(self, text, host, port, kind, display):
  t=c.parse_target(text); self.assertEqual((t.host,t.port,t.kind,t.display_endpoint),(host,port,kind,display))
 def bad(self,*values):
  for value in values:
   with self.subTest(value=value), self.assertRaises(c.TargetError): c.parse_target(value)
 def test_hostnames(self):
  self.ok('example.com','example.com',443,'hostname','example.com:443'); self.ok('localhost','localhost',443,'hostname','localhost:443'); self.ok('EXAMPLE.COM.','EXAMPLE.COM.',443,'hostname','EXAMPLE.COM.:443'); self.ok('a-b:0443','a-b',443,'hostname','a-b:443')
 def test_ipv4(self):
  self.ok('192.0.2.1','192.0.2.1',443,'ipv4','192.0.2.1:443'); self.ok('192.0.2.1:1','192.0.2.1',1,'ipv4','192.0.2.1:1'); self.ok('192.0.2.1:65535','192.0.2.1',65535,'ipv4','192.0.2.1:65535')
 def test_ipv6(self):
  self.ok('2001:0db8:0:0:0:0:0:1','2001:db8::1',443,'ipv6','[2001:db8::1]:443'); self.ok('[2001:db8::1]:8443','2001:db8::1',8443,'ipv6','[2001:db8::1]:8443'); self.ok('2001:db8::1:8443','2001:db8::1:8443',443,'ipv6','[2001:db8::1:8443]:443')
 def test_bad_brackets(self): self.bad('[192.0.2.1]:443','[example.com]:443','[::1]','[::1]:','[::1','::1]','[fe80::1%eth0]:443')
 def test_bad_names(self):
  self.bad('a_b','é.example','a..b','-bad','bad-','a'*64+'.com','a.'*127+'a','has space','bad\nname','https://x','a/b','a?b','a#b','u@h','')
 def test_bad_ports(self): self.bad('x:0','x:65536','x:-1','x:+1','x:1.0','x:1_0','x:١','x: 1',':443')

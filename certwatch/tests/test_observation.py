import importlib.util,pathlib,socket,unittest
P=pathlib.Path(__file__).parents[1]/'certwatch.py'; S=importlib.util.spec_from_file_location('certwatch_o',P); c=importlib.util.module_from_spec(S); import sys; sys.modules[S.name]=c; S.loader.exec_module(c)
class Sock:
 def __init__(self,fail=None,peer=('203.0.113.9',443)): self.fail=fail; self.peer=peer; self.closed=False; self.timeouts=[]
 def settimeout(self,x): self.timeouts.append(x)
 def connect(self,a):
  if self.fail: raise self.fail
 def getpeername(self): return self.peer
 def close(self): self.closed=True
class TLS(Sock):
 def __init__(self,der=b'DER',handshake=None): super().__init__(); self.der=der; self.handshake=handshake
 def do_handshake(self):
  if self.handshake: raise self.handshake
 def getpeercert(self,binary_form=False): self.binary=binary_form; return self.der
class Context:
 def __init__(self,tls): self.tls=tls; self.calls=[]
 def wrap_socket(self,sock,**kw): self.calls.append(kw); return self.tls
class ObservationTests(unittest.TestCase):
 def target(self,x='example.com'): return c.parse_target(x)
 def records(self): return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',443)),(socket.AF_INET6,socket.SOCK_STREAM,6,'',('::1',443,0,0))]
 def test_resolution_signature_and_order(self):
  calls=[]; out=c.resolve_candidates(self.target(),lambda *a:(calls.append(a) or self.records()))
  self.assertEqual(calls[0],('example.com',443,socket.AF_UNSPEC,socket.SOCK_STREAM)); self.assertEqual([x.family for x in out],[socket.AF_INET,socket.AF_INET6])
 def test_no_candidates(self):
  with self.assertRaisesRegex(c.CertWatchError,'no TCP'): c.resolve_candidates(self.target(),lambda *a:[])
 def test_resolution_failure(self):
  def bad(*a): raise socket.gaierror()
  with self.assertRaisesRegex(c.CertWatchError,'resolution failed'): c.resolve_candidates(self.target(),bad)
 def test_tcp_fallback_and_close(self):
  socks=[Sock(OSError()),Sock()]; got=c._connect(c.resolve_candidates(self.target(),lambda *a:self.records()),lambda *a:socks.pop(0)); self.assertFalse(got.closed)
 def test_all_timeout(self):
  socks=[Sock(socket.timeout()),Sock(socket.timeout())]
  with self.assertRaisesRegex(c.CertWatchError,'timed out'): c._connect(c.resolve_candidates(self.target(),lambda *a:self.records()),lambda *a:socks.pop(0))
 def test_mixed_failure(self):
  socks=[Sock(socket.timeout()),Sock(OSError())]
  with self.assertRaisesRegex(c.CertWatchError,'connection failed'): c._connect(c.resolve_candidates(self.target(),lambda *a:self.records()),lambda *a:socks.pop(0))
 def observe(self,target='example.com',tls=None,tcp=None):
  tcp=tcp or Sock(); tls=tls or TLS(); ctx=Context(tls)
  result=c.observe_leaf(self.target(target),lambda *a:self.records()[:1],lambda *a:tcp,lambda:ctx)
  return result,tcp,tls,ctx
 def test_exact_der_peer_sni_cleanup(self):
  result,tcp,tls,ctx=self.observe(); self.assertEqual(result,c.LeafObservation('203.0.113.9',b'DER')); self.assertEqual(ctx.calls[0]['server_hostname'],'example.com'); self.assertTrue(tls.closed); self.assertEqual(tcp.timeouts,[5.0,5.0])
 def test_ip_no_sni(self): self.assertIsNone(self.observe('192.0.2.1')[3].calls[0]['server_hostname'])
 def test_ipv6_peer(self): self.assertEqual(self.observe(tcp=Sock(peer=('2001:db8::1',443,0,0)))[0].connected_address,'[2001:db8::1]')
 def test_empty(self):
  with self.assertRaisesRegex(c.CertWatchError,'did not present'): self.observe(tls=TLS(b''))
 def test_oversized(self):
  with self.assertRaisesRegex(c.CertWatchError,'retrieval failed'): self.observe(tls=TLS(b'x'*(c.MAX_CERTIFICATE_BYTES+1)))
 def test_tls_timeout_no_fallback(self):
  with self.assertRaisesRegex(c.CertWatchError,'handshake timed out'): self.observe(tls=TLS(handshake=socket.timeout()))
 def test_tls_failure(self):
  with self.assertRaisesRegex(c.CertWatchError,'handshake failed'): self.observe(tls=TLS(handshake=OSError()))

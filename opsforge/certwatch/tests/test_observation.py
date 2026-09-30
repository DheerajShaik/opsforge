import importlib.util,pathlib,socket,ssl,unittest
P=pathlib.Path(__file__).parents[1]/'certwatch.py'; S=importlib.util.spec_from_file_location('certwatch_o',P); c=importlib.util.module_from_spec(S); import sys; sys.modules[S.name]=c; S.loader.exec_module(c)
class Sock:
 def __init__(self,fail=None,peer=('203.0.113.9',443)): self.fail=fail; self.peer=peer; self.closed=False; self.timeouts=[]; self.connected=[]
 def settimeout(self,x): self.timeouts.append(x)
 def connect(self,a):
  self.connected.append(a)
  if self.fail: raise self.fail
 def getpeername(self):
  if isinstance(self.peer,BaseException): raise self.peer
  return self.peer
 def close(self): self.closed=True
class TLS(Sock):
 def __init__(self,der=b'DER',handshake=None,chain=None): super().__init__(); self.der=der; self.handshake=handshake; self.chain=chain
 def do_handshake(self):
  if self.handshake: raise self.handshake
 def getpeercert(self,binary_form=False): self.binary=binary_form; return self.der
 def version(self): return 'TLSv1.3'
 def cipher(self): return ('TLS_AES_256_GCM_SHA384','TLSv1.3',256)
 def __enter__(self): return self
 def __exit__(self,*a): self.close()
class ChainTLS(TLS):
 def get_verified_chain(self): return self.chain
class Context:
 def __init__(self,*tls): self.tls=list(tls); self.calls=[]
 def wrap_socket(self,sock,**kw): self.calls.append(kw); return self.tls.pop(0)
def verification_error(message='self-signed certificate'):
 error=ssl.SSLCertVerificationError(1,f'[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: {message}'); error.verify_message=message; error.verify_code=18; return error
class ObservationTests(unittest.TestCase):
 def target(self,x='example.com'): return c.parse_target(x)
 def records(self): return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',443)),(socket.AF_INET6,socket.SOCK_STREAM,6,'',('::1',443,0,0))]
 def test_resolution_signature_and_order(self):
  calls=[]; out=c.resolve_candidates(self.target(),lambda *a:(calls.append(a) or self.records()))
  self.assertEqual(calls[0],('example.com',443,socket.AF_UNSPEC,socket.SOCK_STREAM,0,0)); self.assertEqual([x.family for x in out],[socket.AF_INET,socket.AF_INET6])
 def test_ip_literals_are_resolved_without_a_dns_query(self):
  for target,flags in (('192.0.2.1',socket.AI_NUMERICHOST),('[2001:db8::1]:443',socket.AI_NUMERICHOST),('example.com',0)):
   calls=[]; c.resolve_candidates(self.target(target),lambda *a:(calls.append(a) or self.records()))
   self.assertEqual(calls[0][-1],flags,target)
 def test_no_candidates(self):
  with self.assertRaisesRegex(c.CertWatchError,'name resolution failed: .*empty result'): c.resolve_candidates(self.target(),lambda *a:[])
 def test_resolution_failure(self):
  def bad(*a): raise socket.gaierror()
  with self.assertRaisesRegex(c.CertWatchError,'resolution failed'): c.resolve_candidates(self.target(),bad)
 def test_a_name_that_does_not_exist_says_so(self):
  def gone(*a): raise socket.gaierror(socket.EAI_NONAME,'Name or service not known')
  with self.assertRaisesRegex(c.CertWatchError,'^name resolution failed: name or address was not known$'): c.resolve_candidates(self.target(),gone)
 def test_tcp_fallback_and_close(self):
  socks=[Sock(OSError()),Sock()]; first=socks[0]; got,_=c._connect(c.resolve_candidates(self.target(),lambda *a:self.records()),lambda *a:socks.pop(0)); self.assertFalse(got.closed); self.assertTrue(first.closed)
 def test_all_timeout(self):
  socks=[Sock(socket.timeout()),Sock(socket.timeout())]
  with self.assertRaisesRegex(c.CertWatchError,'timed out'): c._connect(c.resolve_candidates(self.target(),lambda *a:self.records()),lambda *a:socks.pop(0))
 def test_mixed_failure(self):
  socks=[Sock(socket.timeout()),Sock(OSError())]
  with self.assertRaisesRegex(c.CertWatchError,'connection failed'): c._connect(c.resolve_candidates(self.target(),lambda *a:self.records()),lambda *a:socks.pop(0))
 def observe(self,target='example.com',tls=None,tcp=None,fallback=(),sockets=None,records=None):
  tcp=tcp or Sock(); tls=tls or TLS(); verified=Context(tls); unverified=Context(*fallback); socks=sockets or [tcp]; resolved=[]
  def resolver(*a): resolved.append(a); return records or self.records()[:1]
  result=c.observe_endpoint(self.target(target),c.CONNECT_BUDGET_SECONDS,(verified,unverified),resolver,lambda *a:socks.pop(0))
  self.assertEqual(len(resolved),1)
  return result,tcp,tls,verified,unverified
 def test_verified_handshake_supplies_the_leaf_on_one_connection(self):
  result,tcp,tls,ctx,fallback=self.observe(); self.assertEqual((result.connected_address,result.der_certificate),('203.0.113.9',b'DER')); self.assertGreaterEqual(result.tcp_seconds,0); self.assertGreaterEqual(result.tls_seconds,0)
  self.assertEqual(ctx.calls,[{'server_hostname':'example.com','do_handshake_on_connect':False}]); self.assertEqual(fallback.calls,[]); self.assertTrue(tls.binary); self.assertTrue(tls.closed); self.assertEqual(tcp.timeouts,[5.0,5.0])
  self.assertEqual((result.trust_verified,result.verification_error,result.tls_version,result.cipher,result.chain_certificates),(True,None,'TLSv1.3','TLS_AES_256_GCM_SHA384',None))
 def test_chain_count_comes_from_the_verified_handshake(self):
  self.assertEqual(self.observe(tls=ChainTLS(chain=[b'leaf',b'intermediate']))[0].chain_certificates,2)
 def test_verification_failure_reconnects_to_the_same_address_without_verification(self):
  records=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.7',443)),(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.8',443))]
  first,second=Sock(peer=('192.0.2.7',443)),Sock(peer=('192.0.2.7',443)); failed=TLS(handshake=verification_error()); leaf=ChainTLS(der=b'UNTRUSTED',chain=[b'x'])
  result,_,_,verified,unverified=self.observe(tls=failed,fallback=[leaf],sockets=[first,second],records=records)
  self.assertEqual((first.connected,second.connected),([('192.0.2.7',443)],[('192.0.2.7',443)])); self.assertTrue(failed.closed); self.assertTrue(leaf.closed)
  self.assertEqual([len(verified.calls),len(unverified.calls)],[1,1]); self.assertEqual(unverified.calls[0]['server_hostname'],'example.com')
  self.assertEqual((result.der_certificate,result.trust_verified,result.chain_certificates,result.connected_address),(b'UNTRUSTED',False,None,'192.0.2.7'))
  self.assertEqual(result.verification_error,'certificate verification failed: self-signed certificate')
 def test_failed_unverified_retry_is_an_observation_error(self):
  with self.assertRaisesRegex(c.CertWatchError,r'^certificate verification failed: self-signed certificate; the unverified leaf retrieval then failed: TCP connection failed$'):
   self.observe(tls=TLS(handshake=verification_error()),sockets=[Sock(),Sock(ConnectionRefusedError())])
 def test_ip_no_sni(self): self.assertIsNone(self.observe('192.0.2.1')[3].calls[0]['server_hostname'])
 def test_ipv6_peer(self): self.assertEqual(self.observe(tcp=Sock(peer=('2001:db8::1',443,0,0)))[0].connected_address,'[2001:db8::1]')
 def test_peer_disconnect_before_handshake_is_an_observation_error(self):
  tcp=Sock(peer=OSError(107,'Transport endpoint is not connected'))
  with self.assertRaisesRegex(c.CertWatchError,'disconnected before the TLS handshake'): self.observe(tcp=tcp)
  self.assertTrue(tcp.closed)
 def test_empty(self):
  with self.assertRaisesRegex(c.CertWatchError,'did not present'): self.observe(tls=TLS(b''))
 def test_oversized(self):
  with self.assertRaisesRegex(c.CertWatchError,'retrieval failed'): self.observe(tls=TLS(b'x'*(c.MAX_CERTIFICATE_BYTES+1)))
 def test_tls_timeout_no_fallback(self):
  tls=TLS(handshake=socket.timeout())
  with self.assertRaisesRegex(c.CertWatchError,'handshake timed out after 5 seconds'): self.observe(tls=tls)
  self.assertTrue(tls.closed)
 def test_tls_failure_no_fallback(self):
  error=ssl.SSLError(1,'[SSL: WRONG_VERSION_NUMBER] wrong version number'); error.reason='WRONG_VERSION_NUMBER'
  for failure,text in ((OSError(),'handshake failed: OSError'),(error,'handshake failed: WRONG_VERSION_NUMBER')):
   with self.subTest(failure=failure), self.assertRaisesRegex(c.CertWatchError,text): self.observe(tls=TLS(handshake=failure))

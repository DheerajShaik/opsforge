import contextlib,importlib.util,io,pathlib,unittest
from datetime import datetime,timezone,timedelta
from unittest import mock
P=pathlib.Path(__file__).parents[1]/'certwatch.py'; S=importlib.util.spec_from_file_location('certwatch_cli',P); c=importlib.util.module_from_spec(S); import sys; sys.modules[S.name]=c; S.loader.exec_module(c)
class TestCli(unittest.TestCase):
 def invoke(self,args):
  out,err=io.StringIO(),io.StringIO()
  with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
   try: code=c.main(args)
   except SystemExit as e: code=e.code
  return code,out.getvalue(),err.getvalue()
 def test_help(self):
  for flag in ('-h','--help'):
   code,out,err=self.invoke([flag]); self.assertEqual((code,bool(out),err),(0,True,''))
 def test_invalid_invocations(self):
  for args in ([],['a','b'],['--no'],['bad_name'],['x','--warn-days','-1'],['--warn-days','+1','x'],['--warn-days','1.5','x'],['--warn-days','١','x']):
   code,out,err=self.invoke(args); self.assertEqual(code,2); self.assertEqual(out,''); self.assertNotIn('Traceback',err)
 def test_extremely_large_numeric_values_are_invocation_errors(self):
  huge='9'*5000
  for args in ((f'x:{huge}',),('--warn-days',huge,'x')):
   code,out,err=self.invoke(list(args)); self.assertEqual(code,2); self.assertEqual(out,''); self.assertNotIn('internal execution failure',err); self.assertNotIn('Traceback',err)
 def test_decoder_before_network(self):
  with mock.patch.object(c,'find_decoder',side_effect=c.CertWatchError("required decoder 'openssl' is not available")),mock.patch.object(c,'observe_leaf') as observe:
   code,out,err=self.invoke(['example.com']); self.assertEqual(code,3); observe.assert_not_called(); self.assertEqual(out,'')
 def successful(self,status):
  b=datetime(2026,1,1,tzinfo=timezone.utc); cert=c.CertificateInfo('CN=x','CN=i','01',(),b,b+timedelta(days=40),'AA')
  assessment=c.ValidityAssessment(status,timedelta(days=2) if status in (c.ValidityStatus.NORMAL,c.ValidityStatus.WARNING) else None,status is c.ValidityStatus.WARNING,0 if status is c.ValidityStatus.NORMAL else 1)
  with mock.patch.object(c,'find_decoder',return_value='/openssl'),mock.patch.object(c,'observe_leaf',return_value=c.LeafObservation('1.2.3.4',b'x')),mock.patch.object(c,'decode_certificate',return_value=cert),mock.patch.object(c,'assess_validity',return_value=assessment): return self.invoke(['--warn-days','030','example.com'])
 def test_status_outputs(self):
  for status,expected in ((c.ValidityStatus.NORMAL,0),(c.ValidityStatus.WARNING,1),(c.ValidityStatus.EXPIRED,1),(c.ValidityStatus.NOT_YET,1)):
   code,out,err=self.successful(status); self.assertEqual(code,expected); self.assertIn('CertWatch:',out); self.assertEqual(err,'')
 def test_operational_failure(self):
  with mock.patch.object(c,'find_decoder',return_value='/openssl'),mock.patch.object(c,'observe_leaf',side_effect=c.CertWatchError('TCP connection failed')):
   code,out,err=self.invoke(['x']); self.assertEqual((code,out), (3,'')); self.assertEqual(err,'certwatch: TCP connection failed\n')
 def test_internal_and_interrupt(self):
  for error,code,text in ((RuntimeError(),3,'internal execution failure'),(KeyboardInterrupt(),130,'interrupted')):
   with mock.patch.object(c,'find_decoder',side_effect=error): got,out,err=self.invoke(['x'])
   self.assertEqual((got,out),(code,'')); self.assertIn(text,err); self.assertNotIn('Traceback',err)

def load_tests(loader, tests, pattern):
 return loader.loadTestsFromTestCase(TestCli)

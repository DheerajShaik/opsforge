import importlib.util,pathlib,unittest
from datetime import datetime,timezone,timedelta
P=pathlib.Path(__file__).parents[1]/'certwatch.py'; S=importlib.util.spec_from_file_location('certwatch_v',P); c=importlib.util.module_from_spec(S); import sys; sys.modules[S.name]=c; S.loader.exec_module(c)
U=timezone.utc; B=datetime(2026,1,1,tzinfo=U); E=B+timedelta(days=40)
class ValidityTests(unittest.TestCase):
 def a(self,now,w=30): return c.assess_validity(B,E,w,lambda:now)
 def test_before(self): self.assertIs(self.a(B-timedelta(microseconds=1)).status,c.ValidityStatus.NOT_YET)
 def test_exact_start(self): self.assertIs(self.a(B).status,c.ValidityStatus.NORMAL)
 def test_middle(self): self.assertEqual(self.a(B+timedelta(days=20)).exit_code,1)
 def test_exact_end(self): self.assertIs(self.a(E,0).status,c.ValidityStatus.WARNING)
 def test_after(self): self.assertIs(self.a(E+timedelta(microseconds=1),999).status,c.ValidityStatus.EXPIRED)
 def test_threshold_boundaries(self):
  self.assertIs(self.a(E-timedelta(days=30)+timedelta(microseconds=1)).status,c.ValidityStatus.WARNING)
  self.assertIs(self.a(E-timedelta(days=30)).status,c.ValidityStatus.WARNING)
  self.assertIs(self.a(E-timedelta(days=30)-timedelta(microseconds=1)).status,c.ValidityStatus.NORMAL)
 def test_zero(self): self.assertIs(self.a(E-timedelta(microseconds=1),0).status,c.ValidityStatus.NORMAL)
 def test_naive(self):
  with self.assertRaises(ValueError): c.assess_validity(B.replace(tzinfo=None),E,1)
 def test_clock_once(self):
  calls=[]
  def clock(): calls.append(1); return B
  c.assess_validity(B,E,1,clock); self.assertEqual(len(calls),1)
 def test_fraction_display(self): self.assertEqual(c._remaining(timedelta(days=1,seconds=2,microseconds=999)), '1 days, 00:00:02')

import argparse
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portlens


class PortValidationTests(unittest.TestCase):
  def test_valid_boundaries_and_typical_ports(self):
    for value, expected in (("1", 1), ("8080", 8080), ("65535", 65535), ("08080", 8080)):
      with self.subTest(value=value):
        self.assertEqual(portlens.parse_port(value), expected)

  def test_invalid_ports(self):
    for value in ("0", "-1", "65536", "eight", "", " 8080", "8080 ", "8 080"):
      with self.subTest(value=value):
        with self.assertRaises(argparse.ArgumentTypeError):
          portlens.parse_port(value)

  def test_parser_rejects_missing_extra_and_unsupported_arguments(self):
    parser = portlens.build_argument_parser()
    for arguments in ([], ["8080", "8081"], ["--udp", "8080"]):
      with self.subTest(arguments=arguments):
        with self.assertRaises(SystemExit) as context:
          parser.parse_args(arguments)
        self.assertEqual(context.exception.code, 2)


if __name__ == "__main__":
  unittest.main()

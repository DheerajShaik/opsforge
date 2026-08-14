#!/usr/bin/env python3
"""Observe and report the leaf certificate presented by one TLS endpoint."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import selectors
import shutil
import socket
import ssl
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Callable, Optional, Sequence

TCP_TIMEOUT = 5.0
TLS_TIMEOUT = 5.0
DECODER_TIMEOUT = 5.0
MAX_CERTIFICATE_BYTES = 1024 * 1024
MAX_DECODER_OUTPUT = 64 * 1024
UNAVAILABLE = "-"


class CertWatchError(Exception):
    """A stable operational failure."""


class TargetError(ValueError):
    """An invalid CLI target or numeric argument."""


@dataclass(frozen=True)
class Target:
    original: str
    host: str
    port: int
    kind: str
    sni_name: Optional[str]
    display_endpoint: str


@dataclass(frozen=True)
class ConnectionCandidate:
    family: int
    socket_type: int
    protocol: int
    sockaddr: tuple


@dataclass(frozen=True)
class LeafObservation:
    connected_address: str
    der_certificate: bytes


@dataclass(frozen=True)
class CertificateInfo:
    subject: str
    issuer: str
    serial: str
    sans: tuple[tuple[str, str], ...]
    not_before: datetime
    not_after: datetime
    sha256_fingerprint: str


class ValidityStatus(Enum):
    NORMAL = "currently within certificate validity period"
    WARNING = "currently within certificate validity period but inside the configured warning window"
    NOT_YET = "not yet within certificate validity period"
    EXPIRED = "expired"


@dataclass(frozen=True)
class ValidityAssessment:
    status: ValidityStatus
    remaining: Optional[timedelta]
    inside_warning_window: bool
    exit_code: int


def _ascii_decimal(value: str, label: str, minimum: int, maximum: Optional[int] = None) -> int:
    if not value or not re.fullmatch(r"[0-9]+", value, re.ASCII):
        raise TargetError(f"{label} must be an ASCII decimal integer")
    try:
        number = int(value)
    except ValueError as exc:
        # Python may reject extremely long decimal strings; keep this an invocation error.
        raise TargetError(f"{label} must be an ASCII decimal integer") from exc
    if number < minimum or (maximum is not None and number > maximum):
        limit = f" from {minimum} through {maximum}" if maximum is not None else f" of at least {minimum}"
        raise TargetError(f"{label} must be{limit}")
    return number


def _hostname(value: str) -> str:
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise TargetError("hostname must contain ASCII characters only") from exc
    if not value or len(value) > 253 or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in value):
        raise TargetError("invalid hostname")
    rooted = value.endswith(".")
    body = value[:-1] if rooted else value
    labels = body.split(".")
    if not body or any(
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label, re.ASCII)
        for label in labels
    ):
        raise TargetError("invalid hostname")
    return value


def parse_target(value: str) -> Target:
    if not isinstance(value, str) or not value:
        raise TargetError("target is required")
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\[\]]+)\]:([^:]+)", value)
        if not match or "%" in match.group(1):
            raise TargetError("invalid bracketed IPv6 target")
        try:
            ip = ipaddress.IPv6Address(match.group(1))
        except ValueError as exc:
            raise TargetError("bracketed target must contain IPv6") from exc
        port = _ascii_decimal(match.group(2), "port", 1, 65535)
        host = str(ip)
        return Target(value, host, port, "ipv6", None, f"[{host}]:{port}")
    if "[" in value or "]" in value:
        raise TargetError("invalid bracket syntax")
    colons = value.count(":")
    if colons >= 2:
        if "%" in value:
            raise TargetError("scoped IPv6 is not supported")
        try:
            host = str(ipaddress.IPv6Address(value))
        except ValueError as exc:
            raise TargetError("invalid IPv6 target") from exc
        return Target(value, host, 443, "ipv6", None, f"[{host}]:443")
    port = 443
    host_text = value
    if colons == 1:
        host_text, port_text = value.split(":")
        if not host_text:
            raise TargetError("host is required")
        port = _ascii_decimal(port_text, "port", 1, 65535)
    try:
        host = str(ipaddress.IPv4Address(host_text))
        kind, sni = "ipv4", None
    except ValueError:
        host = _hostname(host_text)
        kind, sni = "hostname", host
    return Target(value, host, port, kind, sni, f"{host}:{port}")


def sanitize(value: object) -> str:
    result = []
    for char in str(value):
        code = ord(char)
        category = unicodedata.category(char)
        if char == "\\" or category in {"Cc", "Cf", "Cs", "Zl", "Zp"}:
            if code <= 0xFF:
                result.append(f"\\x{code:02X}")
            elif code <= 0xFFFF:
                result.append(f"\\u{code:04X}")
            else:
                result.append(f"\\U{code:08X}")
        else:
            result.append(char)
    return "".join(result)


def fingerprint(der: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())


def assess_validity(
    not_before: datetime,
    not_after: datetime,
    warn_days: int,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> ValidityAssessment:
    if not_before.tzinfo is None or not_after.tzinfo is None:
        raise ValueError("validity datetimes must be timezone-aware")
    now = clock()
    if now.tzinfo is None:
        raise ValueError("clock must return a timezone-aware datetime")
    now = now.astimezone(timezone.utc)
    if now < not_before:
        return ValidityAssessment(ValidityStatus.NOT_YET, None, False, 1)
    if now > not_after:
        return ValidityAssessment(ValidityStatus.EXPIRED, None, False, 1)
    remaining = not_after - now
    warning = remaining.total_seconds() <= warn_days * 86400
    return ValidityAssessment(
        ValidityStatus.WARNING if warning else ValidityStatus.NORMAL,
        remaining,
        warning,
        1 if warning else 0,
    )


def resolve_candidates(target: Target, resolver=socket.getaddrinfo) -> list[ConnectionCandidate]:
    try:
        records = resolver(target.host, target.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError as exc:
        raise CertWatchError("name resolution failed") from exc
    candidates = [
        ConnectionCandidate(record[0], record[1], record[2], record[4])
        for record in records
        if record[1] == socket.SOCK_STREAM
    ]
    if not candidates:
        raise CertWatchError("name resolution returned no TCP candidates")
    return candidates


def _connect(candidates: list[ConnectionCandidate], socket_factory=socket.socket):
    timed_out = 0
    for candidate in candidates:
        sock = socket_factory(candidate.family, candidate.socket_type, candidate.protocol)
        try:
            sock.settimeout(TCP_TIMEOUT)
            sock.connect(candidate.sockaddr)
            return sock
        except (TimeoutError, socket.timeout):
            timed_out += 1
            sock.close()
        except OSError:
            sock.close()
    if timed_out == len(candidates):
        raise CertWatchError("TCP connection timed out")
    raise CertWatchError("TCP connection failed")


def _peer_address(peer: object) -> str:
    if not isinstance(peer, tuple) or not peer:
        raise CertWatchError("leaf certificate retrieval failed")
    try:
        ip = ipaddress.ip_address(peer[0])
    except (ValueError, TypeError) as exc:
        raise CertWatchError("leaf certificate retrieval failed") from exc
    return f"[{ip}]" if ip.version == 6 else str(ip)


def observe_leaf(
    target: Target,
    resolver=socket.getaddrinfo,
    socket_factory=socket.socket,
    context_factory=lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
) -> LeafObservation:
    candidates = resolve_candidates(target, resolver)
    tcp = _connect(candidates, socket_factory)
    tls = None
    try:
        connected = _peer_address(tcp.getpeername())
        try:
            context = context_factory()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            tcp.settimeout(TLS_TIMEOUT)
            tls = context.wrap_socket(
                tcp,
                server_hostname=target.sni_name,
                do_handshake_on_connect=False,
            )
            tls.settimeout(TLS_TIMEOUT)
            tls.do_handshake()
        except (TimeoutError, socket.timeout) as exc:
            raise CertWatchError("TLS handshake timed out after 5 seconds") from exc
        except Exception as exc:
            raise CertWatchError("TLS handshake failed") from exc
        try:
            der = tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise CertWatchError("leaf certificate retrieval failed") from exc
        if not der:
            raise CertWatchError("peer did not present a leaf certificate")
        if not isinstance(der, bytes) or len(der) > MAX_CERTIFICATE_BYTES:
            raise CertWatchError("leaf certificate retrieval failed")
        return LeafObservation(connected, der)
    finally:
        if tls is not None:
            tls.close()
        else:
            tcp.close()


OPENSSL_ARGS = (
    "x509",
    "-inform",
    "DER",
    "-noout",
    "-subject",
    "-issuer",
    "-serial",
    "-startdate",
    "-enddate",
    "-ext",
    "subjectAltName",
    "-nameopt",
    "RFC2253",
)


def find_decoder(which=shutil.which) -> str:
    path = which("openssl")
    if not path:
        raise CertWatchError("required decoder 'openssl' is not available")
    return os.path.abspath(path)


def _stop_decoder(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def run_decoder(path: str, der: bytes, popen=subprocess.Popen) -> bytes:
    """Decode bounded DER input with a bounded, shell-free OpenSSL subprocess."""
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C"})
    try:
        proc = popen(
            [path, *OPENSSL_ARGS],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except OSError as exc:
        raise CertWatchError("could not execute certificate decoder") from exc

    if proc.stdin is None or proc.stdout is None or proc.stderr is None:
        _stop_decoder(proc)
        raise CertWatchError("could not execute certificate decoder")

    selector = selectors.DefaultSelector()
    data = {"out": bytearray(), "err": bytearray()}
    input_view = memoryview(der)
    input_offset = 0
    deadline = time.monotonic() + DECODER_TIMEOUT

    try:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
        selector.register(proc.stdin, selectors.EVENT_WRITE, "in")
        selector.register(proc.stdout, selectors.EVENT_READ, "out")
        selector.register(proc.stderr, selectors.EVENT_READ, "err")

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            events = selector.select(remaining)
            if not events:
                raise TimeoutError
            for key, _ in events:
                if key.data == "in":
                    try:
                        written = os.write(
                            key.fileobj.fileno(),
                            input_view[input_offset : input_offset + 8192],
                        )
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        input_offset = len(input_view)
                    else:
                        input_offset += written
                    if input_offset >= len(input_view):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                else:
                    try:
                        chunk = os.read(key.fileobj.fileno(), 8192)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    data[key.data].extend(chunk)
                    if len(data[key.data]) > MAX_DECODER_OUTPUT:
                        raise OverflowError

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        try:
            status = proc.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError from exc
    except TimeoutError as exc:
        _stop_decoder(proc)
        raise CertWatchError("certificate decoder timed out after 5 seconds") from exc
    except OverflowError as exc:
        _stop_decoder(proc)
        raise CertWatchError("certificate decoder returned oversized output") from exc
    except OSError as exc:
        _stop_decoder(proc)
        raise CertWatchError("certificate decoder failed") from exc
    finally:
        selector.close()
        input_view.release()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    if status != 0:
        raise CertWatchError("certificate decoder failed")
    if not data["out"]:
        raise CertWatchError("certificate decoder returned malformed output")
    return bytes(data["out"])


def _parse_time(value: str) -> datetime:
    if not re.fullmatch(
        r"[A-Z][a-z]{2} {1,2}[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4} GMT",
        value,
    ):
        raise ValueError
    return datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)


def _split_sans(text: str) -> tuple[tuple[str, str], ...]:
    # Split only unescaped separators. Escaped commas are rejected conservatively below.
    parts = re.split(r"(?<!\\),\s*", text.strip())
    values = []
    labels = {"DNS": "DNS", "IP Address": "IP", "URI": "URI", "email": "email"}
    for part in parts:
        match = re.fullmatch(r"(DNS|IP Address|URI|email):(.+)", part)
        if not match or "\\," in match.group(2):
            raise ValueError
        label, value = labels[match.group(1)], match.group(2)
        if label == "IP":
            value = str(ipaddress.ip_address(value))
        if any(unicodedata.category(char) in {"Cc", "Cs", "Zl", "Zp"} for char in value):
            raise ValueError
        values.append((label, value))
    return tuple(sorted(set(values), key=lambda item: (item[0], item[1])))


def parse_certificate_output(raw: bytes, der: bytes) -> CertificateInfo:
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise CertWatchError("certificate decoder returned malformed output") from exc
    try:
        if "\x00" in text:
            raise ValueError
        lines = text.splitlines()
        fields: dict[str, str] = {}
        san_text = None
        index = 0
        prefixes = {
            "subject=": "subject",
            "issuer=": "issuer",
            "serial=": "serial",
            "notBefore=": "not_before",
            "notAfter=": "not_after",
        }
        while index < len(lines):
            line = lines[index]
            found = next(
                ((prefix, key) for prefix, key in prefixes.items() if line.startswith(prefix)),
                None,
            )
            if found:
                prefix, key = found
                if key in fields:
                    raise ValueError
                fields[key] = line[len(prefix) :]
            elif re.fullmatch(r"X509v3 Subject Alternative Name:(?: critical)?", line):
                if san_text is not None or index + 1 >= len(lines):
                    raise ValueError
                index += 1
                san_text = lines[index].strip()
            elif line.strip():
                raise ValueError
            index += 1

        if set(fields) != {"subject", "issuer", "serial", "not_before", "not_after"}:
            raise ValueError
        # An empty subject DN is valid when identity is carried by a critical SAN.
        if not fields["issuer"]:
            raise ValueError
        if not re.fullmatch(r"[0-9A-Fa-f]+", fields["serial"]):
            raise ValueError
        before = _parse_time(fields["not_before"])
        after = _parse_time(fields["not_after"])
        if after < before:
            raise CertWatchError("certificate contains unusable validity fields")
        sans = () if san_text is None else _split_sans(san_text)
        return CertificateInfo(
            fields["subject"],
            fields["issuer"],
            fields["serial"].upper(),
            sans,
            before,
            after,
            fingerprint(der),
        )
    except CertWatchError:
        raise
    except (ValueError, TypeError) as exc:
        raise CertWatchError("certificate decoder returned malformed output") from exc


def decode_certificate(path: str, der: bytes) -> CertificateInfo:
    return parse_certificate_output(run_decoder(path, der), der)


def _remaining(value: Optional[timedelta]) -> str:
    if value is None:
        return UNAVAILABLE
    seconds = int(value.total_seconds())
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{days} days, {hours:02d}:{minutes:02d}:{seconds:02d}"


def render_report(
    target: Target,
    observation: LeafObservation,
    cert: CertificateInfo,
    assessment: ValidityAssessment,
) -> str:
    sans = ", ".join(f"{kind}:{sanitize(value)}" for kind, value in cert.sans) or UNAVAILABLE
    subject = sanitize(cert.subject) if cert.subject else UNAVAILABLE
    issuer = sanitize(cert.issuer) if cert.issuer else UNAVAILABLE
    serial = cert.serial or UNAVAILABLE
    if assessment.status is ValidityStatus.NORMAL:
        words = [
            "The presented leaf certificate is currently within its encoded validity period.",
            "It is outside the configured expiration warning window.",
        ]
    elif assessment.status is ValidityStatus.WARNING:
        words = [
            "The presented leaf certificate is currently within its encoded validity period but is inside the configured expiration warning window."
        ]
    elif assessment.status is ValidityStatus.NOT_YET:
        words = ["The presented leaf certificate is not yet within its encoded validity period."]
    else:
        words = ["The presented leaf certificate is past the end of its encoded validity period."]
    words.append("CA trust and hostname identity were not assessed.")
    return "\n".join(
        [
            f"CertWatch: {sanitize(target.display_endpoint)}",
            "Scope: leaf TLS certificate presented by the selected endpoint",
            "",
            "Target",
            f"  Requested:          {sanitize(target.display_endpoint)}",
            f"  Connected address:  {sanitize(observation.connected_address)}",
            "",
            "Certificate",
            f"  Subject:       {subject}",
            f"  Issuer:        {issuer}",
            f"  Serial:        {serial}",
            f"  SHA256:        {cert.sha256_fingerprint}",
            f"  Not before:    {cert.not_before:%Y-%m-%dT%H:%M:%SZ}",
            f"  Not after:     {cert.not_after:%Y-%m-%dT%H:%M:%SZ}",
            f"  SANs:          {sans}",
            "",
            "Validity",
            f"  Status:        {assessment.status.value}",
            f"  Remaining:     {_remaining(assessment.remaining)}",
            "",
            "Assessment",
            *[f"  {line}" for line in words],
            "",
        ]
    )


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"certwatch: error: {message}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="certwatch",
        description="Observe one remote TLS leaf certificate and assess its encoded validity period.",
    )
    parser.add_argument("target", help="HOST, HOST:PORT, bare IPv6, or [IPv6]:PORT")
    parser.add_argument(
        "--warn-days",
        default="30",
        metavar="N",
        help="non-negative expiration warning threshold (default: 30)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        try:
            warn_days = _ascii_decimal(args.warn_days, "--warn-days", 0)
            target = parse_target(args.target)
        except TargetError as exc:
            print(f"certwatch: {sanitize(exc)}", file=sys.stderr)
            return 2
        decoder = find_decoder()  # Mandatory local prerequisite precedes all network activity.
        observation = observe_leaf(target)
        certificate = decode_certificate(decoder, observation.der_certificate)
        assessment = assess_validity(certificate.not_before, certificate.not_after, warn_days)
        print(render_report(target, observation, certificate, assessment), end="")
        return assessment.exit_code
    except KeyboardInterrupt:
        print("certwatch: interrupted", file=sys.stderr)
        return 130
    except CertWatchError as exc:
        print(f"certwatch: {sanitize(exc)}", file=sys.stderr)
        return 3
    except Exception:
        print("certwatch: internal execution failure", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

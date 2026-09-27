#!/usr/bin/env python3
"""Observe and report the leaf certificate presented by one TLS endpoint."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import re
import socket
import ssl
import sys
import time
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Callable, Optional, Sequence

from opsforge_common import (
    OutputError,
    OutputRecord,
    add_output_arguments,
    emit_output,
    make_conclusion,
    sanitize_text as sanitize,
    validate_output_arguments,
)
from opsforge_common.process import (
    ProcessOutputLimitError,
    ProcessSpawnError,
    ProcessTimeoutError,
    resolve_executable,
    run_bounded,
)

TCP_TIMEOUT = 5.0
TLS_TIMEOUT = 5.0
CONNECT_BUDGET_SECONDS = 20.0
DECODER_TIMEOUT = 5.0
MAX_CERTIFICATE_BYTES = 1024 * 1024
MAX_DECODER_OUTPUT = 64 * 1024
UNAVAILABLE = "-"
MAX_TARGETS = 32
MAX_RESOLVER_CANDIDATES = 16
DEFAULT_CRITICAL_DAYS = 7
STATUS_RANK = {"VALID": 0, "WARNING": 1, "DRIFT": 2, "CRITICAL": 3, "FAIL": 4, "EXPIRED": 5, "ERROR": 6}


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
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    tcp_seconds: float = 0.0
    tls_seconds: float = 0.0
    candidate: Optional[ConnectionCandidate] = None


@dataclass(frozen=True)
class VerificationEvidence:
    trust_verified: Optional[bool]
    hostname_verified: Optional[bool]
    verification_error: Optional[str]
    chain_certificates: Optional[int] = None
    leaf_matches_observation: Optional[bool] = None


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
    CRITICAL = "currently within certificate validity period but inside the configured critical window"
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
        # RFC 6066 forbids a trailing dot in SNI even though the resolver accepts one.
        kind, sni = "hostname", host.rstrip(".")
    return Target(value, host, port, kind, sni, f"{host}:{port}")


def fingerprint(der: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())


def assess_validity(
    not_before: datetime,
    not_after: datetime,
    warn_days: int,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    critical_days: int | None = None,
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
    critical = critical_days is not None and remaining.total_seconds() <= critical_days * 86400
    return ValidityAssessment(
        ValidityStatus.CRITICAL if critical else ValidityStatus.WARNING if warning else ValidityStatus.NORMAL,
        remaining,
        warning,
        1 if warning or critical else 0,
    )


def resolve_candidates(target: Target, resolver=socket.getaddrinfo) -> list[ConnectionCandidate]:
    try:
        records = resolver(target.host, target.port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError as exc:
        raise CertWatchError("name resolution failed") from exc
    candidates = []
    seen = set()
    for record in records:
        if record[1] != socket.SOCK_STREAM:
            continue
        candidate = ConnectionCandidate(record[0], record[1], record[2], record[4])
        key = (candidate.family, candidate.socket_type, candidate.protocol, candidate.sockaddr)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(candidate)
        if len(candidates) >= MAX_RESOLVER_CANDIDATES:
            break
    if not candidates:
        raise CertWatchError("name resolution returned no TCP candidates")
    return candidates


def _connect(
    candidates: list[ConnectionCandidate], socket_factory=socket.socket, budget: float = CONNECT_BUDGET_SECONDS,
) -> tuple[socket.socket, ConnectionCandidate]:
    """Connect to the first reachable candidate within one overall budget; return the socket and candidate."""
    deadline = time.monotonic() + budget
    timed_out = 0
    for candidate in candidates:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise CertWatchError("TCP connection timed out")
        try:
            sock = socket_factory(candidate.family, candidate.socket_type, candidate.protocol)
        except OSError:
            continue
        try:
            sock.settimeout(min(TCP_TIMEOUT, remaining))
            sock.connect(candidate.sockaddr)
            return sock, candidate
        except (TimeoutError, socket.timeout):
            timed_out += 1
            sock.close()
        except OSError:
            sock.close()
        except BaseException:
            sock.close()
            raise
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


def _handshake_reason(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    return str(reason) if reason else type(exc).__name__


def observe_leaf(
    target: Target,
    resolver=socket.getaddrinfo,
    socket_factory=socket.socket,
    context_factory=lambda: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
) -> LeafObservation:
    candidates = resolve_candidates(target, resolver)
    tcp_started = time.monotonic()
    tcp, candidate = _connect(candidates, socket_factory)
    tcp_seconds = time.monotonic() - tcp_started
    tls = None
    try:
        try:
            connected = _peer_address(tcp.getpeername())
        except OSError as exc:
            raise CertWatchError("TCP peer disconnected before the TLS handshake") from exc
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
            tls_started = time.monotonic()
            tls.do_handshake()
            tls_seconds = time.monotonic() - tls_started
        except (TimeoutError, socket.timeout) as exc:
            raise CertWatchError(f"TLS handshake timed out after {TLS_TIMEOUT:g} seconds") from exc
        except (ssl.SSLError, OSError, ValueError) as exc:
            raise CertWatchError(f"TLS handshake failed: {_handshake_reason(exc)}") from exc
        try:
            der = tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError, ValueError) as exc:
            raise CertWatchError("leaf certificate retrieval failed") from exc
        if not der:
            raise CertWatchError("peer did not present a leaf certificate")
        if not isinstance(der, bytes) or len(der) > MAX_CERTIFICATE_BYTES:
            raise CertWatchError("leaf certificate retrieval failed")
        version_method = getattr(tls, "version", None)
        cipher_method = getattr(tls, "cipher", None)
        version = version_method() if callable(version_method) else None
        cipher_value = cipher_method() if callable(cipher_method) else None
        cipher = cipher_value[0] if isinstance(cipher_value, tuple) and cipher_value else None
        return LeafObservation(connected, der, version, cipher, tcp_seconds, tls_seconds, candidate)
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


def find_decoder(which=resolve_executable) -> str:
    path = which("openssl")
    if not path:
        raise CertWatchError("required decoder 'openssl' is not available in a trusted PATH directory")
    return path


def run_decoder(path: str, der: bytes) -> bytes:
    """Decode bounded DER input with a bounded, shell-free OpenSSL subprocess."""
    try:
        result = run_bounded(
            [path, *OPENSSL_ARGS], timeout=DECODER_TIMEOUT, max_output_bytes=MAX_DECODER_OUTPUT, stdin_data=der,
        )
    except ProcessTimeoutError as exc:
        raise CertWatchError(f"certificate decoder timed out after {DECODER_TIMEOUT:g} seconds") from exc
    except ProcessOutputLimitError as exc:
        raise CertWatchError("certificate decoder returned oversized output") from exc
    except ProcessSpawnError as exc:
        raise CertWatchError("could not execute certificate decoder") from exc
    except OSError as exc:
        raise CertWatchError("certificate decoder failed") from exc
    if result.returncode != 0:
        raise CertWatchError("certificate decoder failed")
    if not result.stdout:
        raise CertWatchError("certificate decoder returned malformed output")
    return result.stdout


def _parse_time(value: str) -> datetime:
    if not re.fullmatch(
        r"[A-Z][a-z]{2} {1,2}[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4} GMT",
        value,
    ):
        raise ValueError
    return datetime.strptime(value, "%b %d %H:%M:%S %Y GMT").replace(tzinfo=timezone.utc)


def _split_sans(text: str) -> tuple[tuple[str, str], ...]:
    # Split only unescaped separators; DNS and IP values stay strict because identity depends on them.
    parts = re.split(r"(?<!\\),\s*", text.strip())
    values = []
    labels = {"DNS": "DNS", "IP Address": "IP", "URI": "URI", "email": "email"}
    for part in parts:
        match = re.fullmatch(r"(DNS|IP Address|URI|email):(.+)", part)
        if not match:
            if not part or any(unicodedata.category(char) in {"Cc", "Cs", "Zl", "Zp"} for char in part):
                raise ValueError
            values.append(("other", part))
            continue
        label, value = labels[match.group(1)], match.group(2)
        if label in {"DNS", "IP"} and "\\," in value:
            raise ValueError
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
            # OpenSSL may append ASCII horizontal whitespace to this heading.
            elif re.fullmatch(r"X509v3 Subject Alternative Name:(?: critical)?[ \t]*", line):
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


def verify_hostname(target: Target, certificate: CertificateInfo) -> Optional[bool]:
    """Verify identity from parsed SANs against the name a client would verify: SNI when sent, else the IP."""
    expected_name = target.sni_name.rstrip(".").lower() if target.sni_name else None
    if expected_name is not None:
        identities = [value.rstrip(".").lower() for kind, value in certificate.sans if kind == "DNS"]
    else:
        identities = [value for kind, value in certificate.sans if kind == "IP"]
    if not identities:
        return False if certificate.sans else None
    if expected_name is None:
        try:
            expected = ipaddress.ip_address(target.host)
            return any(ipaddress.ip_address(value) == expected for value in identities)
        except ValueError:
            return False
    for pattern in identities:
        if "*" not in pattern and pattern == expected_name:
            return True
        if pattern.startswith("*.") and pattern.count("*") == 1:
            suffix = pattern[2:]
            if suffix.count(".") >= 1 and expected_name.count(".") == suffix.count(".") + 1:
                if expected_name.endswith("." + suffix):
                    return True
    return False


def verify_endpoint(
    target: Target,
    certificate: CertificateInfo,
    resolver=socket.getaddrinfo,
    socket_factory=socket.socket,
    context_factory=ssl.create_default_context,
    candidate: Optional[ConnectionCandidate] = None,
) -> VerificationEvidence:
    """Perform a bounded CA-trust handshake, on the observed address when known, plus a SAN identity check."""
    identity = verify_hostname(target, certificate)
    tcp = None
    tls = None
    try:
        candidates = [candidate] if candidate is not None else resolve_candidates(target, resolver)
        tcp, _ = _connect(candidates, socket_factory)
        tcp.settimeout(TLS_TIMEOUT)
        context = context_factory()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        tls = context.wrap_socket(tcp, server_hostname=target.sni_name)
        chain_method = getattr(tls, "get_verified_chain", None)
        chain_count = len(chain_method()) if callable(chain_method) else None
        verified_der = tls.getpeercert(binary_form=True)
        if not isinstance(verified_der, bytes) or not verified_der or len(verified_der) > MAX_CERTIFICATE_BYTES:
            return VerificationEvidence(
                None, identity, "trusted handshake leaf certificate was unavailable", chain_count, False,
            )
        matched = fingerprint(verified_der) == certificate.sha256_fingerprint
        if matched:
            return VerificationEvidence(True, identity, None, chain_count, True)
        return VerificationEvidence(
            None, identity, "trusted handshake presented a different leaf certificate; the observed leaf's trust is unknown",
            chain_count, False,
        )
    except ssl.SSLCertVerificationError as exc:
        return VerificationEvidence(False, identity, sanitize(exc)[:256], None)
    except (OSError, ssl.SSLError, CertWatchError) as exc:
        return VerificationEvidence(None, identity, f"verification handshake unavailable: {sanitize(exc)[:192]}", None)
    finally:
        if tls is not None:
            tls.close()
        elif tcp is not None:
            tcp.close()


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
    verification: VerificationEvidence | None = None,
    baseline_changed: bool | None = None,
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
    elif assessment.status is ValidityStatus.CRITICAL:
        words = [
            "The presented leaf certificate is currently within its encoded validity period but is inside the configured critical expiration window."
        ]
    elif assessment.status is ValidityStatus.NOT_YET:
        words = ["The presented leaf certificate is not yet within its encoded validity period."]
    else:
        words = ["The presented leaf certificate is past the end of its encoded validity period."]
    if verification is None:
        words.append("CA trust and hostname identity were not assessed.")
    else:
        words.append("Revocation status was not checked.")
    return "\n".join(
        [
            f"CertWatch: {sanitize(target.display_endpoint)}",
            "Scope: leaf TLS certificate presented by the selected endpoint",
            "",
            "Target",
            f"  Requested:          {sanitize(target.display_endpoint)}",
            f"  Connected address:  {sanitize(observation.connected_address)}",
            f"  SNI:                {sanitize(target.sni_name) if target.sni_name else UNAVAILABLE}",
            f"  TCP duration:       {observation.tcp_seconds:.3f} seconds",
            f"  TLS duration:       {observation.tls_seconds:.3f} seconds",
            f"  TLS version:        {sanitize(observation.tls_version) if observation.tls_version else UNAVAILABLE}",
            f"  Cipher:             {sanitize(observation.cipher) if observation.cipher else UNAVAILABLE}",
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
            "Verification",
            f"  CA trust:      {_trust_label(verification)}",
            f"  Host identity: {('verified' if verification.hostname_verified else 'mismatch') if verification and verification.hostname_verified is not None else 'unavailable'}",
            f"  Trusted leaf:  {('matched' if verification.leaf_matches_observation else 'different') if verification and verification.leaf_matches_observation is not None else 'unavailable'}",
            f"  Chain count:   {verification.chain_certificates if verification and verification.chain_certificates is not None else UNAVAILABLE}",
            f"  Baseline:      {('changed' if baseline_changed else 'unchanged') if baseline_changed is not None else 'not supplied'}",
            "",
            "Assessment",
            *[f"  {line}" for line in words],
            "",
        ]
    )


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"certwatch: error: {sanitize(message)}\n")


def _trust_label(verification: Optional[VerificationEvidence]) -> str:
    if verification is None or verification.trust_verified is None:
        return "not assessed"
    return "verified" if verification.trust_verified else "not verified"


def classify_target(
    assessment: ValidityAssessment, verification: VerificationEvidence, baseline_changed: Optional[bool],
) -> str:
    """Return the most severe per-target condition so drift never hides expiry."""
    conditions = ["VALID"]
    validity = {
        ValidityStatus.EXPIRED: "EXPIRED", ValidityStatus.NOT_YET: "FAIL",
        ValidityStatus.CRITICAL: "CRITICAL", ValidityStatus.WARNING: "WARNING",
    }
    if assessment.status in validity:
        conditions.append(validity[assessment.status])
    if baseline_changed:
        conditions.append("DRIFT")
    if (
        verification.trust_verified is not True
        or verification.hostname_verified is not True
        or verification.leaf_matches_observation is not True
    ):
        conditions.append("WARNING")
    return max(conditions, key=STATUS_RANK.__getitem__)


def aggregate_status(statuses: Sequence[str]) -> str:
    if statuses and all(status == "ERROR" for status in statuses):
        return "ERROR"
    if "ERROR" in statuses:
        return "PARTIAL"
    return max(statuses, key=STATUS_RANK.__getitem__) if statuses else "ERROR"


def render_failure(target: Target, detail: str) -> str:
    return "\n".join([
        f"CertWatch: {sanitize(target.display_endpoint)}",
        "Scope: leaf TLS certificate presented by the selected endpoint",
        "",
        "Observation",
        "  Status:        ERROR",
        f"  Detail:        {detail}",
    ])


def build_parser() -> argparse.ArgumentParser:
    parser = Parser(
        prog="certwatch",
        description="Observe bounded remote TLS certificates and separate validity, identity, and trust evidence.",
    )
    parser.add_argument("target", nargs="+", help="one or more HOST, HOST:PORT, bare IPv6, or [IPv6]:PORT targets (maximum 32)")
    parser.add_argument(
        "--warn-days",
        default="30",
        metavar="N",
        help="non-negative expiration warning threshold (default: 30)",
    )
    parser.add_argument(
        "--critical-days", default=None, metavar="N",
        help=f"non-negative critical expiration threshold (default: the smaller of {DEFAULT_CRITICAL_DAYS} and --warn-days)",
    )
    parser.add_argument("--sni", metavar="HOST", help="explicit ASCII SNI name (single target only); identity is verified against it")
    parser.add_argument("--baseline-sha256", metavar="HEX", help="compare the leaf SHA-256 fingerprint with an explicit baseline (single target only)")
    add_output_arguments(parser)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    started = time.monotonic()
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        validate_output_arguments(parser, args)
        try:
            warn_days = _ascii_decimal(args.warn_days, "--warn-days", 0)
            if args.critical_days is None:
                critical_days = min(DEFAULT_CRITICAL_DAYS, warn_days)
            else:
                critical_days = _ascii_decimal(args.critical_days, "--critical-days", 0)
            if warn_days > 36500 or critical_days > 36500:
                raise TargetError("warning thresholds must not exceed 36500 days")
            if critical_days > warn_days:
                raise TargetError("--critical-days must not exceed --warn-days")
            if len(args.target) > MAX_TARGETS:
                raise TargetError(f"at most {MAX_TARGETS} targets may be inspected")
            targets = [parse_target(value) for value in args.target]
            if args.sni is not None:
                if len(targets) != 1:
                    raise TargetError("--sni requires exactly one target")
                try:
                    ipaddress.ip_address(args.sni)
                except ValueError:
                    pass
                else:
                    raise TargetError("--sni must be a hostname; TLS clients do not send IP literals as SNI")
                sni = _hostname(args.sni).rstrip(".")
                targets[0] = replace(targets[0], sni_name=sni)
            baseline = None
            if args.baseline_sha256 is not None:
                if len(targets) != 1:
                    raise TargetError("--baseline-sha256 requires exactly one target")
                baseline = args.baseline_sha256.replace(":", "").upper()
                if not re.fullmatch(r"[0-9A-F]{64}", baseline):
                    raise TargetError("--baseline-sha256 must contain exactly 64 hexadecimal digits")
        except TargetError as exc:
            print(f"certwatch: {sanitize(exc)}", file=sys.stderr)
            return 2
        decoder = find_decoder()  # Mandatory local prerequisite precedes all network activity.
        reports = []
        observations = []
        warnings = []
        exit_code = 0
        statuses = []
        for target in targets:
            try:
                observation = observe_leaf(target)
                certificate = decode_certificate(decoder, observation.der_certificate)
                assessment = assess_validity(
                    certificate.not_before, certificate.not_after, warn_days,
                    critical_days=critical_days,
                )
                verification = verify_endpoint(target, certificate, candidate=observation.candidate)
                baseline_changed = None if baseline is None else certificate.sha256_fingerprint.replace(":", "") != baseline
                status = classify_target(assessment, verification, baseline_changed)
                exit_code = max(exit_code, assessment.exit_code)
                if status != "VALID":
                    exit_code = max(exit_code, 1)
                if verification.verification_error:
                    warnings.append(f"{target.display_endpoint}: {verification.verification_error}")
                report = render_report(target, observation, certificate, assessment, verification, baseline_changed)
                reports.append(report.rstrip())
                statuses.append(status)
                observations.append({
                    "target": target.display_endpoint,
                    "connected_address": observation.connected_address,
                    "sni": target.sni_name,
                    "tls_version": observation.tls_version,
                    "cipher": observation.cipher,
                    "tcp_seconds": observation.tcp_seconds,
                    "tls_seconds": observation.tls_seconds,
                    "certificate": certificate,
                    "validity_status": assessment.status.name,
                    "remaining_seconds": assessment.remaining.total_seconds() if assessment.remaining is not None else None,
                    "trust_verified": verification.trust_verified,
                    "hostname_verified": verification.hostname_verified,
                    "trusted_leaf_matches_observation": verification.leaf_matches_observation,
                    "chain_certificates": verification.chain_certificates,
                    "revocation_checked": False,
                    "baseline_changed": baseline_changed,
                })
            except CertWatchError as exc:
                detail = sanitize(exc)
                warnings.append(f"{target.display_endpoint}: {detail}")
                reports.append(render_failure(target, detail))
                statuses.append("ERROR")
                observations.append({"target": target.display_endpoint, "error": detail})
                exit_code = 3
        overall_status = aggregate_status(statuses)
        if overall_status == "VALID":
            finding = f"all {len(statuses)} target certificate observations were valid and verified"
            next_action = "no certificate-layer issue was detected; revocation was not checked"
        elif "ERROR" in statuses:
            finding = f"{statuses.count('ERROR')} of {len(statuses)} target observations failed"
            next_action = "review the target-specific warning and retry only the failed endpoint"
        else:
            finding = f"certificate attention is required for {sum(status != 'VALID' for status in statuses)} of {len(statuses)} targets"
            next_action = "review validity, identity, trust, and baseline evidence separately"
        target_label = targets[0].display_endpoint if len(targets) == 1 else f"{len(targets)} TLS targets"
        conclusion = make_conclusion(overall_status, target_label, finding, next_action)
        brief = "\n".join([
            f"Targets: {len(targets)}",
            *[f"{target.display_endpoint}: {status}" for target, status in zip(targets, statuses)],
        ])
        record = OutputRecord(
            tool="certwatch",
            status=overall_status,
            target=target_label,
            observations={"targets": observations, "warning_days": warn_days, "critical_days": critical_days},
            conclusion=conclusion,
            next_action=next_action + ".",
            warnings=warnings,
            elapsed_seconds=time.monotonic() - started,
        )
        for warning in warnings:
            print(f"certwatch: warning: {warning}", file=sys.stderr)
        emit_output(
            record,
            detailed="\n\n".join(reports),
            brief=brief,
            json_mode=args.json,
            brief_mode=args.brief,
            quiet=args.quiet,
            output_path=args.output,
            force=args.force,
        )
        return exit_code
    except KeyboardInterrupt:
        print("certwatch: interrupted", file=sys.stderr)
        return 130
    except CertWatchError as exc:
        print(f"certwatch: {sanitize(exc)}", file=sys.stderr)
        return 3
    except OutputError as exc:
        print(f"certwatch: {sanitize(exc)}", file=sys.stderr)
        return 3
    except Exception:
        print("certwatch: internal execution failure", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

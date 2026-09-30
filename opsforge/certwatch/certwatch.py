#!/usr/bin/env python3
"""Observe and report the leaf certificate presented by one TLS endpoint."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import queue
import re
import socket
import ssl
import sys
import threading
import time
import unicodedata
from dataclasses import dataclass, replace
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Callable, Optional, Sequence

from opsforge.common import (
    OutputError,
    OutputRecord,
    add_output_arguments,
    emit_output,
    make_conclusion,
    sanitize_text as sanitize,
    validate_output_arguments,
)
from opsforge.common.net import (
    MAX_CANDIDATES,
    Candidate,
    HostError,
    NetworkAPIError,
    connect_first,
    parse_host,
    parse_sni,
    resolve_tcp,
    sni_name,
)
from opsforge.common.process import (
    ProcessOutputLimitError,
    ProcessSpawnError,
    ProcessTimeoutError,
    resolve_executable,
    run_bounded,
)
from opsforge.common.status import (
    CRITICAL,
    ERROR,
    EXIT_FAILURE,
    EXIT_FINDING,
    EXIT_INTERRUPTED,
    EXIT_OK,
    EXIT_USAGE,
    INCOMPLETE,
    SKIPPED,
    WARNING,
)

TCP_TIMEOUT = 5.0
RESOLVE_TIMEOUT = 5.0
TLS_TIMEOUT = 5.0
CONNECT_BUDGET_SECONDS = 20.0
TOTAL_BUDGET_SECONDS = 120.0
DEADLINE_GRACE_SECONDS = 1.0
DECODER_TIMEOUT = 5.0
MAX_CERTIFICATE_BYTES = 1024 * 1024
MAX_DECODER_OUTPUT = 64 * 1024
UNAVAILABLE = "-"
MAX_TARGETS = 32
MAX_PARALLEL_TARGETS = 8
DEFAULT_CRITICAL_DAYS = 7
VALID = "VALID"
DRIFT = "DRIFT"
NOT_YET_VALID = "NOT_YET_VALID"
EXPIRED = "EXPIRED"
# VALID and the findings, least to most severe; ERROR and SKIPPED are gaps, not findings.
STATUS_RANK = {VALID: 0, WARNING: 1, DRIFT: 2, CRITICAL: 3, NOT_YET_VALID: 4, EXPIRED: 5}
# OpenSSL joins subjectAltName entries with ", "; a split must also precede a GeneralName label.
SAN_SEPARATOR = re.compile(r", (?=(?:othername|X400Name|EdiPartyName|email|DNS|URI|DirName|IP Address|Registered ID):)")


class CertWatchError(Exception):
    """A stable operational failure."""


class TargetError(ValueError):
    """An invalid CLI target or numeric argument."""


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    sni_name: Optional[str]
    display_endpoint: str


@dataclass(frozen=True)
class LeafObservation:
    connected_address: str
    der_certificate: bytes
    tls_version: Optional[str]
    cipher: Optional[str]
    tcp_seconds: float
    tls_seconds: float
    trust_verified: bool
    verification_error: Optional[str] = None
    chain_certificates: Optional[int] = None
    resolution_truncated: bool = False

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


@dataclass(frozen=True)
class RunOptions:
    targets: tuple[Target, ...]
    warn_days: int
    critical_days: int
    baseline: Optional[str]


@dataclass(frozen=True)
class TargetOutcome:
    status: str
    report: str
    observation: dict
    warnings: tuple[str, ...]


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
        return Target(host, port, None, f"[{host}]:{port}")
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
        return Target(host, 443, None, f"[{host}]:443")
    port = 443
    host_text = value
    if colons == 1:
        host_text, port_text = value.split(":")
        if not host_text:
            raise TargetError("host is required")
        port = _ascii_decimal(port_text, "port", 1, 65535)
    try:
        host, kind = parse_host(host_text, "hostname")
    except HostError as exc:
        raise TargetError(str(exc)) from exc
    return Target(host, port, sni_name(host, kind), f"{host}:{port}")


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
        return ValidityAssessment(ValidityStatus.NOT_YET, None)
    if now > not_after:
        return ValidityAssessment(ValidityStatus.EXPIRED, None)
    remaining = not_after - now
    warning = remaining.total_seconds() <= warn_days * 86400
    critical = critical_days is not None and remaining.total_seconds() <= critical_days * 86400
    return ValidityAssessment(
        ValidityStatus.CRITICAL if critical else ValidityStatus.WARNING if warning else ValidityStatus.NORMAL,
        remaining,
    )


def _host_kind(host: str) -> str:
    try:
        return f"ipv{ipaddress.ip_address(host).version}"
    except ValueError:
        return "hostname"


def resolve_target(target: Target, resolver=socket.getaddrinfo, timeout: Optional[float] = None):
    try:
        resolution = resolve_tcp(
            target.host, target.port, _host_kind(target.host), resolver=resolver, timeout=timeout,
        )
    except NetworkAPIError as exc:
        raise CertWatchError(f"name resolution failed: {exc}") from exc
    if resolution.failure is not None:
        raise CertWatchError(f"name resolution failed: {resolution.failure}")
    return resolution


def resolve_candidates(target: Target, resolver=socket.getaddrinfo) -> list[Candidate]:
    return list(resolve_target(target, resolver).candidates)


def _connect(
    candidates: list[Candidate], socket_factory=socket.socket, budget: float = CONNECT_BUDGET_SECONDS,
) -> tuple[socket.socket, Candidate]:
    """Connect to the first reachable candidate within one overall budget; return the socket and candidate."""
    try:
        sock, attempts = connect_first(
            candidates, timeout=TCP_TIMEOUT, deadline=time.monotonic() + budget, socket_factory=socket_factory,
        )
    except TimeoutError as exc:
        raise CertWatchError("TCP connection timed out") from exc
    except NetworkAPIError as exc:
        raise CertWatchError("TCP connection failed") from exc
    if sock is None:
        if attempts and all(attempt.outcome == "timed out" for attempt in attempts):
            raise CertWatchError("TCP connection timed out")
        raise CertWatchError("TCP connection failed")
    return sock, attempts[-1].candidate


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


def tls_contexts() -> tuple[ssl.SSLContext, ssl.SSLContext]:
    """Return the CA-verifying and the unverified client contexts that every target of one run shares."""
    verified = ssl.create_default_context()
    # Identity is judged from the decoded SANs so that it stays separate from CA trust.
    verified.check_hostname = False
    # Python 3.13+ sets these by default; setting them everywhere keeps trust verdicts version-independent.
    verified.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN | ssl.VERIFY_X509_STRICT
    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    return verified, unverified


def _handshake(tcp: socket.socket, context: ssl.SSLContext, target: Target) -> tuple[ssl.SSLSocket, float]:
    """Complete one bounded TLS handshake on a connected socket, closing it on any failure."""
    tls = None
    try:
        try:
            tcp.settimeout(TLS_TIMEOUT)
            tls = context.wrap_socket(tcp, server_hostname=target.sni_name, do_handshake_on_connect=False)
            started = time.monotonic()
            tls.do_handshake()
            return tls, time.monotonic() - started
        except ssl.SSLCertVerificationError:
            raise
        except TimeoutError as exc:
            raise CertWatchError(f"TLS handshake timed out after {TLS_TIMEOUT:g} seconds") from exc
        except (ssl.SSLError, OSError, ValueError) as exc:
            raise CertWatchError(f"TLS handshake failed: {_handshake_reason(exc)}") from exc
    except BaseException:
        (tcp if tls is None else tls).close()
        raise


def observe_endpoint(
    target: Target,
    budget: float = CONNECT_BUDGET_SECONDS,
    contexts: Optional[tuple[ssl.SSLContext, ssl.SSLContext]] = None,
    resolver=socket.getaddrinfo,
    socket_factory=socket.socket,
) -> LeafObservation:
    """Read the leaf from a CA-verifying handshake; only if verification fails, reconnect to the same address unverified."""
    verified, unverified = tls_contexts() if contexts is None else contexts
    resolution = resolve_target(target, resolver, RESOLVE_TIMEOUT)
    candidates = list(resolution.candidates)
    started = time.monotonic()
    tcp, candidate = _connect(candidates, socket_factory, budget)
    tcp_seconds = time.monotonic() - started
    try:
        connected = _peer_address(tcp.getpeername())
    except OSError as exc:
        tcp.close()
        raise CertWatchError("TCP peer disconnected before the TLS handshake") from exc
    except BaseException:
        tcp.close()
        raise
    failure = None
    try:
        tls, tls_seconds = _handshake(tcp, verified, target)
    except ssl.SSLCertVerificationError as exc:
        failure = f"certificate verification failed: {getattr(exc, 'verify_message', None) or exc}"
        try:
            started = time.monotonic()
            tcp, _ = _connect([candidate], socket_factory, budget)
            tcp_seconds = time.monotonic() - started
            tls, tls_seconds = _handshake(tcp, unverified, target)
        except CertWatchError as retry:
            raise CertWatchError(f"{failure}; the unverified leaf retrieval then failed: {retry}") from retry
    with tls:
        try:
            der = tls.getpeercert(binary_form=True)
        except (OSError, ValueError) as exc:
            raise CertWatchError("leaf certificate retrieval failed") from exc
        if not der:
            raise CertWatchError("peer did not present a leaf certificate")
        if len(der) > MAX_CERTIFICATE_BYTES:
            raise CertWatchError("leaf certificate retrieval failed")
        # SSLSocket.get_verified_chain() is public from Python 3.13.
        chain_method = getattr(tls, "get_verified_chain", None) if failure is None else None
        cipher = tls.cipher()
        return LeafObservation(
            connected, der, tls.version(), cipher[0] if cipher else None, tcp_seconds, tls_seconds,
            failure is None, failure, len(chain_method()) if callable(chain_method) else None,
            resolution.truncated,
        )


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
    values = []
    labels = {"DNS": "DNS", "IP Address": "IP", "URI": "URI", "email": "email"}
    for part in SAN_SEPARATOR.split(text.strip()):
        match = re.fullmatch(r"(DNS|IP Address|URI|email):(.+)", part)
        if not match:
            if not part or any(unicodedata.category(char) in {"Cc", "Cs", "Zl", "Zp"} for char in part):
                raise ValueError
            values.append(("other", part))
            continue
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


def _remaining(value: Optional[timedelta]) -> str:
    if value is None:
        return UNAVAILABLE
    seconds = int(value.total_seconds())
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{days} days, {hours:02d}:{minutes:02d}:{seconds:02d}"


def _display_name(value: str) -> str:
    # OpenSSL's RFC 2253 form is already escaped printable ASCII; doubling its backslashes would misquote it.
    return value if value.isascii() and value.isprintable() else sanitize(value)


def render_report(
    target: Target,
    observation: LeafObservation,
    cert: CertificateInfo,
    assessment: ValidityAssessment,
    hostname_verified: Optional[bool],
    baseline_changed: Optional[bool],
) -> str:
    sans = ", ".join(f"{kind}:{sanitize(value)}" for kind, value in cert.sans) or UNAVAILABLE
    subject = _display_name(cert.subject) if cert.subject else UNAVAILABLE
    issuer = _display_name(cert.issuer) if cert.issuer else UNAVAILABLE
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
            f"  CA trust:      {'verified' if observation.trust_verified else 'not verified'}",
            f"  Host identity: {'unavailable' if hostname_verified is None else 'verified' if hostname_verified else 'mismatch'}",
            f"  Trusted leaf:  {'matched' if observation.trust_verified else 'unavailable'}",
            f"  Chain count:   {UNAVAILABLE if observation.chain_certificates is None else observation.chain_certificates}",
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
        self.exit(EXIT_USAGE, f"certwatch: error: {sanitize(message)}\n")


def classify_target(
    assessment: ValidityAssessment, trust_verified: bool, hostname_verified: Optional[bool],
    baseline_changed: Optional[bool],
) -> str:
    """Return the most severe per-target condition so drift never hides expiry."""
    conditions = [VALID]
    validity = {
        ValidityStatus.EXPIRED: EXPIRED, ValidityStatus.NOT_YET: NOT_YET_VALID,
        ValidityStatus.CRITICAL: CRITICAL, ValidityStatus.WARNING: WARNING,
    }
    if assessment.status in validity:
        conditions.append(validity[assessment.status])
    if baseline_changed:
        conditions.append(DRIFT)
    if not trust_verified or hostname_verified is not True:
        conditions.append(WARNING)
    return max(conditions, key=STATUS_RANK.__getitem__)


def aggregate_status(statuses: Sequence[str]) -> str:
    """The most severe finding wins over gaps; without one, any ERROR or SKIPPED target leaves the run INCOMPLETE."""
    findings = [status for status in statuses if STATUS_RANK.get(status, 0) > 0]
    if findings:
        return max(findings, key=STATUS_RANK.__getitem__)
    valid = statuses.count(VALID)
    if not valid:
        return ERROR
    return VALID if valid == len(statuses) else INCOMPLETE


def render_failure(target: Target, status: str, detail: str) -> str:
    return "\n".join([
        f"CertWatch: {sanitize(target.display_endpoint)}",
        "Scope: leaf TLS certificate presented by the selected endpoint",
        "",
        "Observation",
        f"  Status:        {status}",
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


def parse_options(args: argparse.Namespace) -> RunOptions:
    """Validate thresholds and targets beyond argparse; raise TargetError for invocation errors."""
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
            explicit = parse_sni(args.sni, "--sni")
        except HostError as exc:
            raise TargetError(str(exc)) from exc
        targets[0] = replace(targets[0], sni_name=explicit)
    baseline = None
    if args.baseline_sha256 is not None:
        if len(targets) != 1:
            raise TargetError("--baseline-sha256 requires exactly one target")
        baseline = args.baseline_sha256.replace(":", "").upper()
        if not re.fullmatch(r"[0-9A-F]{64}", baseline):
            raise TargetError("--baseline-sha256 must contain exactly 64 hexadecimal digits")
    return RunOptions(tuple(targets), warn_days, critical_days, baseline)


def unobserved_target(target: Target, status: str, detail: str) -> TargetOutcome:
    return TargetOutcome(
        status, render_failure(target, status, detail),
        {"target": target.display_endpoint, "status": status, "error": detail},
        (f"{target.display_endpoint}: {detail}",),
    )


def inspect_target(
    target: Target, decoder: str, options: RunOptions, budget: float, contexts: tuple[ssl.SSLContext, ssl.SSLContext],
) -> TargetOutcome:
    try:
        observation = observe_endpoint(target, budget, contexts)
        certificate = decode_certificate(decoder, observation.der_certificate)
    except CertWatchError as exc:
        return unobserved_target(target, ERROR, sanitize(exc))
    assessment = assess_validity(
        certificate.not_before, certificate.not_after, options.warn_days, critical_days=options.critical_days,
    )
    identity = verify_hostname(target, certificate)
    baseline_changed = (
        None if options.baseline is None else certificate.sha256_fingerprint.replace(":", "") != options.baseline
    )
    status = classify_target(assessment, observation.trust_verified, identity, baseline_changed)
    warnings = (
        (f"{target.display_endpoint}: {sanitize(observation.verification_error)}",)
        if observation.verification_error else ()
    )
    if observation.resolution_truncated:
        warnings += (
            f"{target.display_endpoint}: the resolver returned more than {MAX_CANDIDATES} addresses; only the first {MAX_CANDIDATES} were tried",
        )
    observation_record = {
        "target": target.display_endpoint,
        "status": status,
        "connected_address": observation.connected_address,
        "sni": target.sni_name,
        "tls_version": observation.tls_version,
        "cipher": observation.cipher,
        "tcp_seconds": observation.tcp_seconds,
        "tls_seconds": observation.tls_seconds,
        "certificate": certificate,
        "validity_status": assessment.status.name,
        "remaining_seconds": assessment.remaining.total_seconds() if assessment.remaining is not None else None,
        "trust_verified": observation.trust_verified,
        "hostname_verified": identity,
        "trusted_leaf_matches_observation": True if observation.trust_verified else None,
        "chain_certificates": observation.chain_certificates,
        "revocation_checked": False,
        "baseline_changed": baseline_changed,
    }
    report = render_report(target, observation, certificate, assessment, identity, baseline_changed).rstrip()
    return TargetOutcome(status, report, observation_record, warnings)


def inspect_targets(
    options: RunOptions, decoder: str, clock: Callable[[], float] = time.monotonic,
) -> list[TargetOutcome]:
    """Inspect up to MAX_PARALLEL_TARGETS targets at once, keeping input order; at the limit, running targets are ERROR and queued ones SKIPPED."""
    deadline = clock() + TOTAL_BUDGET_SECONDS
    # Waiting uses the real clock so an injected test clock cannot stretch it.
    wait_until = time.monotonic() + TOTAL_BUDGET_SECONDS + DEADLINE_GRACE_SECONDS
    contexts = tls_contexts()
    pending: queue.SimpleQueue = queue.SimpleQueue()
    for item in enumerate(options.targets):
        pending.put(item)
    outcomes: list[Optional[TargetOutcome]] = [None] * len(options.targets)
    failures: list[BaseException] = []
    started: set[int] = set()

    def work() -> None:
        try:
            while not failures:
                try:
                    index, target = pending.get_nowait()
                except queue.Empty:
                    return
                started.add(index)
                remaining = deadline - clock()
                if remaining > 0:
                    budget = min(CONNECT_BUDGET_SECONDS, remaining)
                    outcomes[index] = inspect_target(target, decoder, options, budget, contexts)
                else:
                    outcomes[index] = unobserved_target(
                        target, SKIPPED, f"not attempted: the {TOTAL_BUDGET_SECONDS:g}-second overall time limit was reached",
                    )
        except BaseException as exc:
            failures.append(exc)

    # Daemon workers let an interrupt end the run without waiting for in-flight network I/O.
    workers = [threading.Thread(target=work, daemon=True) for _ in range(min(MAX_PARALLEL_TARGETS, len(options.targets)))]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(max(0.0, wait_until - time.monotonic()))
    if failures:
        raise failures[0]
    finished = list(outcomes)
    started_indexes = set(started)
    return [
        outcome if outcome is not None else unobserved_target(target, *(
            (ERROR, f"did not finish within the {TOTAL_BUDGET_SECONDS:g}-second overall time limit")
            if index in started_indexes else
            (SKIPPED, f"not attempted: the {TOTAL_BUDGET_SECONDS:g}-second overall time limit was reached")
        ))
        for index, (outcome, target) in enumerate(zip(finished, options.targets))
    ]


def summarize(options: RunOptions, outcomes: Sequence[TargetOutcome], started: float) -> tuple[OutputRecord, str, str]:
    """Build the output record, detailed report, and brief report for all target outcomes."""
    statuses = [outcome.status for outcome in outcomes]
    overall_status = aggregate_status(statuses)
    total, failed, skipped = len(statuses), statuses.count(ERROR), statuses.count(SKIPPED)
    gaps = " and ".join(text for count, text in ((failed, f"{failed} failed"), (skipped, f"{skipped} not attempted")) if count)
    if overall_status == VALID:
        finding = f"all {total} target certificate observations were valid and verified"
        next_action = "no certificate-layer issue was detected; revocation was not checked"
    elif overall_status in (ERROR, INCOMPLETE):
        finding = f"{failed + skipped} of {total} target observations did not complete ({gaps})"
        next_action = "review the target-specific warnings and retry the endpoints that did not complete"
    else:
        attention = sum(STATUS_RANK.get(status, 0) > 0 for status in statuses)
        finding = f"certificate attention is required for {attention} of {total} targets"
        next_action = "review validity, identity, trust, and baseline evidence separately"
        if gaps:
            finding += f"; {failed + skipped} other target observations did not complete ({gaps})"
            next_action += ", then retry the endpoints that did not complete"
    targets = options.targets
    target_label = targets[0].display_endpoint if len(targets) == 1 else f"{len(targets)} TLS targets"
    brief = "\n".join([
        f"Targets: {len(targets)}",
        *[f"{target.display_endpoint}: {status}" for target, status in zip(targets, statuses)],
    ])
    record = OutputRecord(
        tool="certwatch",
        status=overall_status,
        target=target_label,
        observations={
            "targets": [outcome.observation for outcome in outcomes],
            "warning_days": options.warn_days,
            "critical_days": options.critical_days,
        },
        conclusion=make_conclusion(overall_status, target_label, finding, next_action),
        next_action=next_action + ".",
        warnings=[warning for outcome in outcomes for warning in outcome.warnings],
        elapsed_seconds=time.monotonic() - started,
    )
    return record, "\n\n".join(outcome.report for outcome in outcomes), brief


def main(argv: Optional[Sequence[str]] = None) -> int:
    started = time.monotonic()
    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        validate_output_arguments(parser, args)
        try:
            options = parse_options(args)
        except TargetError as exc:
            print(f"certwatch: {sanitize(exc)}", file=sys.stderr)
            return EXIT_USAGE
        decoder = find_decoder()  # Mandatory local prerequisite precedes all network activity.
        outcomes = inspect_targets(options, decoder)
        record, detailed, brief = summarize(options, outcomes, started)
        for warning in record.warnings:
            print(f"certwatch: warning: {warning}", file=sys.stderr)
        emit_output(
            record,
            detailed=detailed,
            brief=brief,
            json_mode=args.json,
            brief_mode=args.brief,
            quiet=args.quiet,
            output_path=args.output,
            force=args.force,
        )
        if record.status == VALID:
            return EXIT_OK
        return EXIT_FINDING if record.status in STATUS_RANK else EXIT_FAILURE
    except KeyboardInterrupt:
        print("certwatch: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except CertWatchError as exc:
        print(f"certwatch: {sanitize(exc)}", file=sys.stderr)
        return EXIT_FAILURE
    except OutputError as exc:
        print(f"certwatch: {sanitize(exc)}", file=sys.stderr)
        return EXIT_FAILURE
    except Exception:
        print("certwatch: internal execution failure", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import datetime as dt
import ipaddress
import os
import re
import tempfile
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _atomic_write(path: Path, data: bytes):
    """Write data to path atomically so concurrent readers never see a partial file."""
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def describe_cert(der: bytes) -> dict:
    """Summarize a DER-encoded certificate for ground-truth comparison/logging."""
    cert = x509.load_der_x509_certificate(der)

    def cn(name: x509.Name) -> str | None:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else (name.rfc4514_string() or None)

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        for g in ext:
            if isinstance(g, x509.DNSName):
                sans.append(g.value)
            elif isinstance(g, x509.IPAddress):
                sans.append(str(g.value))
    except x509.ExtensionNotFound:
        pass

    now = dt.datetime.now(dt.UTC)
    nbf, naf = cert.not_valid_before_utc, cert.not_valid_after_utc
    return {
        "subject_cn": cn(cert.subject),
        "issuer_cn": cn(cert.issuer),
        "self_signed": cert.subject == cert.issuer,
        "not_before": nbf.isoformat(),
        "not_after": naf.isoformat(),
        "expired": now > naf or now < nbf,
        "sans": sans,
        "serial": format(cert.serial_number, "x"),
    }

@dataclass
class CertMaterial:
    strategy: str
    certfile: str
    keyfile: str
    hostname: str | None = None


@dataclass
class LeafSpec:
    """Describes one forged leaf certificate, isolating a single validation defect."""
    host: str
    self_signed: bool = False
    expired: bool = False
    include_san: bool = True
    san_host: str | None = None          # SAN dNSName/iPAddress (defaults to host)
    key_size: int = 2048
    sig_hash: object = field(default_factory=lambda: hashes.SHA256())

class CertificateFactory:
    def __init__(self, workdir: str, operator_cert: str | None = None, operator_key: str | None = None):
        self.workdir = Path(workdir) / "certs"
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.operator_cert = operator_cert
        self.operator_key = operator_key
        self._locks: dict[tuple[str, str], threading.Lock] = defaultdict(threading.Lock)
        self._locks_guard = threading.Lock()
        self._ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Trustfall Ephemeral CA")])
        now = dt.datetime.now(dt.UTC)
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer).public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         key_encipherment=False, content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )

    def available_strategies(self, requested: str = "all") -> list[str]:
        base = [
            "self_signed_match", "private_ca_match", "private_ca_wrong_host",
            "cn_only_match", "wildcard_mismatch", "weak_key", "expired_match",
        ]
        if self.operator_cert and self.operator_key:
            base.append("public_wrong_host")
        if requested == "all":
            return base
        mapping = {
            "self-signed": ["self_signed_match"],
            "private-ca": ["private_ca_match", "private_ca_wrong_host"],
            "cn-only": ["cn_only_match"],
            "wildcard": ["wildcard_mismatch"],
            "weak-key": ["weak_key"],
            "public-wrong-host": ["public_wrong_host"] if self.operator_cert and self.operator_key else [],
            "expired": ["expired_match"],
        }
        return mapping.get(requested, [requested])

    def material_for(self, strategy: str, sni: str | None, dest_ip: str) -> CertMaterial:
        host = sni or dest_ip
        wrong = "wrong-host.trustfall.invalid"
        if strategy == "public_wrong_host":
            if not self.operator_cert or not self.operator_key:
                raise ValueError("public_wrong_host requires --cert and --key")
            return CertMaterial(strategy, self.operator_cert, self.operator_key, hostname=wrong)
        # Each strategy isolates one validation defect. Host-validation variants and
        # the expired/weak-sig leaves chain to the ephemeral CA so acceptance among
        # CA-trusting devices points squarely at the named defect, not chain checks.
        specs = {
            "self_signed_match": LeafSpec(host, self_signed=True),
            "private_ca_match": LeafSpec(host),
            "private_ca_wrong_host": LeafSpec(wrong),
            "cn_only_match": LeafSpec(host, include_san=False),
            "wildcard_mismatch": LeafSpec(host, san_host="*." + host),
            "weak_key": LeafSpec(host, key_size=1024),
            "expired_match": LeafSpec(host, expired=True),
        }
        if strategy not in specs:
            raise ValueError(f"unknown strategy {strategy}")
        return self._leaf(strategy, specs[strategy])

    def _lock_for(self, key: tuple[str, str]) -> threading.Lock:
        with self._locks_guard:
            return self._locks[key]

    def _leaf(self, strategy: str, spec: LeafSpec) -> CertMaterial:
        host = spec.host
        safe = SAFE.sub("_", host)[:80]
        certfile = self.workdir / f"{safe}_{strategy}.crt"
        keyfile = self.workdir / f"{safe}_{strategy}.key"
        if certfile.exists() and keyfile.exists():
            return CertMaterial(strategy, str(certfile), str(keyfile), hostname=host)

        with self._lock_for((strategy, safe)):
            # Double-checked: another thread may have generated this pair while we
            # waited for the lock.
            if certfile.exists() and keyfile.exists():
                return CertMaterial(strategy, str(certfile), str(keyfile), hostname=host)

            key = rsa.generate_private_key(public_exponent=65537, key_size=spec.key_size)
            subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
            issuer_cert = None if spec.self_signed else self._ca_cert
            issuer_key = key if spec.self_signed else self._ca_key
            issuer = subject if spec.self_signed else issuer_cert.subject
            now = dt.datetime.now(dt.UTC)
            if spec.expired:
                nbf = now - dt.timedelta(days=30); naf = now - dt.timedelta(days=1)
            else:
                nbf = now - dt.timedelta(hours=1); naf = now + dt.timedelta(days=30)
            builder = (
                x509.CertificateBuilder()
                .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(nbf).not_valid_after(naf)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            )
            if spec.include_san:
                san_host = spec.san_host or host
                try:
                    san = x509.IPAddress(ipaddress.ip_address(san_host))
                except ValueError:
                    san = x509.DNSName(san_host)
                builder = builder.add_extension(x509.SubjectAlternativeName([san]), critical=False)
            cert = builder.sign(issuer_key, spec.sig_hash)
            chain = cert.public_bytes(serialization.Encoding.PEM)
            if not spec.self_signed:
                chain += self._ca_cert.public_bytes(serialization.Encoding.PEM)
            # Write the key first: callers gate on certfile.exists(), so the cert
            # must only appear once its key is already on disk.
            _atomic_write(keyfile, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
            _atomic_write(certfile, chain)
            return CertMaterial(strategy, str(certfile), str(keyfile), hostname=host)

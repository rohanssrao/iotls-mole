from __future__ import annotations

import datetime as dt

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from iotls_mole.certs import CertificateFactory


def _load_pems(path: str) -> list[x509.Certificate]:
    data = open(path, "rb").read()
    return x509.load_pem_x509_certificates(data)


def test_expired_strategy_chains_to_ca_and_is_expired(tmp_path):
    # Regression: expired_match used to be self-signed, confounding expiry with
    # chain validation. It must now chain to the ephemeral CA and be expired.
    factory = CertificateFactory(str(tmp_path))
    material = factory.material_for("expired_match", sni="device.local", dest_ip="10.0.0.5")

    chain = _load_pems(material.certfile)
    assert len(chain) == 2, "expired leaf should ship with the ephemeral CA cert"

    leaf = chain[0]
    assert leaf.not_valid_after_utc < dt.datetime.now(dt.UTC), "leaf must be expired"
    # Leaf is issued by the CA, not self-signed.
    assert leaf.issuer != leaf.subject
    assert leaf.issuer == chain[1].subject


def test_self_signed_strategy_is_single_cert(tmp_path):
    factory = CertificateFactory(str(tmp_path))
    material = factory.material_for("self_signed_match", sni="device.local", dest_ip="10.0.0.5")
    chain = _load_pems(material.certfile)
    assert len(chain) == 1
    assert chain[0].issuer == chain[0].subject


def test_available_strategies_without_operator_cert(tmp_path):
    factory = CertificateFactory(str(tmp_path))
    assert "public_wrong_host" not in factory.available_strategies("all")
    assert factory.available_strategies("public-wrong-host") == []


def test_cn_only_has_no_san(tmp_path):
    factory = CertificateFactory(str(tmp_path))
    material = factory.material_for("cn_only_match", sni="device.local", dest_ip="10.0.0.5")
    leaf = _load_pems(material.certfile)[0]
    try:
        leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        assert False, "cn_only cert must not carry a SAN"
    except x509.ExtensionNotFound:
        pass
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "device.local"


def test_wildcard_mismatch_san(tmp_path):
    factory = CertificateFactory(str(tmp_path))
    material = factory.material_for("wildcard_mismatch", sni="a.b.example.com", dest_ip="10.0.0.5")
    leaf = _load_pems(material.certfile)[0]
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    # A wildcard one level too deep never matches the bare host -> mismatch under test.
    assert san.get_values_for_type(x509.DNSName) == ["*.a.b.example.com"]


def test_weak_key_is_1024_bit(tmp_path):
    factory = CertificateFactory(str(tmp_path))
    material = factory.material_for("weak_key", sni="device.local", dest_ip="10.0.0.5")
    leaf = _load_pems(material.certfile)[0]
    assert leaf.public_key().key_size == 1024
    assert len(_load_pems(material.certfile)) == 2  # chains to CA

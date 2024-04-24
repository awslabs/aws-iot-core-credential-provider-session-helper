"""Create temporary X.509 certificates for testing.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
"""

import datetime
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_selfsigned_rsa2048_cert() -> Tuple[bytes, bytes]:
    """Create RSA 2048 self-signed certificate."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        # backend=default_backend(),
    )
    public_key = private_key.public_key()

    # Set basic constraints that in can sign itself and no other certs.
    basic_constraints = x509.BasicConstraints(ca=True, path_length=0)
    start_date = datetime.datetime(
        year=2023, month=1, day=15, hour=0, minute=0, second=0
    )

    x509_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Colorado"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Denver"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Helper Testing Inc."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Python Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "rsa2048.valid.example.com"),
        ]
    )
    subject_key = x509.SubjectKeyIdentifier.from_public_key(public_key)
    authority_key = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509_name,
        )
        .issuer_name(
            x509_name,
        )
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_date)
        .not_valid_after(start_date + datetime.timedelta(days=30))
        .add_extension(subject_key, critical=False)
        .add_extension(authority_key, critical=False)
        .add_extension(basic_constraints, critical=True)
        .sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )
    )
    return certificate.public_bytes(
        serialization.Encoding.PEM
    ), private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_selfsigned_ec256_cert() -> Tuple[bytes, bytes]:
    """Create RSA 2048 self-signed certificate."""
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
    )
    public_key = private_key.public_key()

    # Set basic constraints that in can sign itself and no other certs.
    basic_constraints = x509.BasicConstraints(ca=False, path_length=None)
    key_usage = x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        data_encipherment=True,
        content_commitment=True,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    start_date = datetime.datetime.utcnow() - datetime.timedelta(days=1)

    x509_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Colorado"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Denver"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Helper Testing Inc."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Python Tests"),
            x509.NameAttribute(NameOID.COMMON_NAME, "ec256.valid.example.com"),
        ]
    )
    subject_key = x509.SubjectKeyIdentifier.from_public_key(public_key)
    authority_key = x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509_name,
        )
        .issuer_name(
            x509_name,
        )
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(start_date)
        .not_valid_after(start_date + datetime.timedelta(days=30))
        .add_extension(subject_key, critical=False)
        .add_extension(authority_key, critical=False)
        .add_extension(key_usage, critical=True)
        .add_extension(basic_constraints, critical=True)
        .sign(
            private_key=private_key,
            algorithm=hashes.SHA256(),
        )
    )
    return certificate.public_bytes(
        serialization.Encoding.PEM
    ), private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

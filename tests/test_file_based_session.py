"""Test cases for the iot_core_credential_provider module.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

These tests focus on testing the session via files or values for certificates and private keys.
"""

import datetime
import os
import platform
import ssl
from pathlib import Path

import certificates
import pytest
import pytest_httpserver
import trustme
from awscrt.io import LogLevel
from botocore.exceptions import ClientError

from awsiot_credentialhelper.boto3_session import Boto3SessionProvider


# Create temporary self-signed certificates for testing. Note: these are crafted
# to test various operating systems, so are explicitly defined with non-standard
# values/subjects and expiration times.

# Files are create and stored in tests/assets and reused if they already exist. This is to
# support development and testing on macOS where the awscrt stored certificates when first used.
# If testing returns coverage errors, especially with reversed lines such as 120->118, open
# Keychain Access, select the Imported Private Key of rsa2048.valid.example.com (twirl open), then
# Get Info->Access Control->"Allow all applications to access this item".

RSA_CERTIFICATE_FILE = Path("tests/assets/rsa2048.valid.example.com.pem")
RSA_PRIVATE_KEY_FILE = Path("tests/assets/rsa2048.valid.example.com.key")
EC_CERTIFICATE_FILE = Path("tests/assets/ec256.valid.example.com.pem")
EC_PRIVATE_KEY_FILE = Path("tests/assets/ec256.valid.example.com.key")
if not RSA_CERTIFICATE_FILE.exists():
    # Generate RSA certificate and private key
    certificate, private_key = certificates.generate_selfsigned_rsa2048_cert()
    with open(RSA_CERTIFICATE_FILE, "w") as f:
        f.write(certificate.decode("utf-8"))
    with open(RSA_PRIVATE_KEY_FILE, "w") as f:
        f.write(private_key.decode("utf-8"))

    # Generate EC certificate and private key
    certificate, private_key = certificates.generate_selfsigned_ec256_cert()
    with open(EC_CERTIFICATE_FILE, "w") as f:
        f.write(certificate.decode("utf-8"))
    with open(EC_PRIVATE_KEY_FILE, "w") as f:
        f.write(private_key.decode("utf-8"))

cert_bytes = b"cert bytes"
key_bytes = b"key bytes"

# OS types for defining test server
if "GITHUB_RUNNER" in os.environ:
    if os.environ["GITHUB_RUNNER"] == "ubuntu-latest":  # pragma: no cover
        # Force IPv6 which is what awscrt will prefer
        server_endpoint = "::1"
    else:
        server_endpoint = "localhost"  # pragma: no cover
else:
    # All others will default to IPv4
    server_endpoint = "localhost"
os_type = platform.system()
if os_type == "Linux":  # pragma: no cover
    cert_file = EC_CERTIFICATE_FILE
    key_file = EC_PRIVATE_KEY_FILE
else:  # pragma: no cover
    cert_file = RSA_CERTIFICATE_FILE
    key_file = RSA_PRIVATE_KEY_FILE


@pytest.fixture(scope="session")
def httpserver_listen_address():
    """Return an address for the test HTTP server."""
    return (server_endpoint, 7939)


@pytest.fixture(scope="session")
def ca():
    """Create CA for mTLS testing."""
    return trustme.CA()


@pytest.fixture(scope="session")
def httpserver_ssl_context(ca):
    """Create an HTTPS server with the CA certificate."""
    # For crypto testing, each OS has difference nuances.
    if os_type == "Linux":  # pragma: no cover
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(EC_CERTIFICATE_FILE))
    else:  # pragma: no cover
        # macOS and Windows work without server requesting cert
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    localhost_cert = ca.issue_cert(
        "localhost",
        "127.0.0.1",
        "::1",
    )
    localhost_cert.configure_cert(context)
    return context


def test_get_session_with_files() -> None:
    """Verify session can be created, now with logging check!"""
    session = Boto3SessionProvider(
        endpoint="my_endpoint.credentials.iot.us-west-2.amazonaws.com",
        role_alias="iot_role_alias",
        certificate=str(cert_file),
        private_key=str(key_file),
        thing_name="my_iot_thing_name",
        awscrt_log_level=LogLevel.NoLogs,
    )
    assert session is not None
    session_default = session.get_session()
    assert session_default is not None
    session_region = session.get_session(region_name="us-west2")
    assert session_region is not None


def test_get_session_with_variables() -> None:
    """Create session object with cert/key as variables."""
    session = Boto3SessionProvider(
        endpoint="cicd_testing.credentials.iot.us-west-2.amazonaws.com",
        role_alias="iot_role_alias",
        certificate=cert_bytes,
        private_key=key_bytes,
        thing_name="my_iot_thing_name",
    )
    assert session is not None


def test_session_with_invalid_credentials() -> None:
    """Verify IoT credential provider endpoint can be hit - invalid credentials.

    Expectation: TLS session will not complete.
    """
    with pytest.raises(
        ValueError,
        match="Error completing mTLS connection to endpoint "
        + "cicd_testing.credentials.iot.us-west-2.amazonaws.com",
    ):
        Boto3SessionProvider(
            endpoint="cicd_testing.credentials.iot.us-west-2.amazonaws.com",
            role_alias="iot_role_alias",
            # certificate=f"tests/assets/{file_prefix}.pem",
            # private_key=f"tests/assets/{file_prefix}.key",
            certificate=str(cert_file),
            private_key=str(key_file),
            thing_name="my_iot_thing_name",
            awscrt_log_level=LogLevel.Trace,
        ).get_session().client("sts").get_caller_identity()


def test_valid_credentials(
    httpserver: pytest_httpserver.HTTPServer,
    ca: trustme.CA,
) -> None:
    """Test call to localhost where response is valid temporary credentials.

    Note: The actual call to get sts credentials will fail, this is to exercise
        the awscrt portions in making HTTPS requests.
    """
    one_hour_later = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    if server_endpoint == "::1":  # pragma: no cover
        endpoint = f"[{server_endpoint}]:7939"
    else:  # pragma: no cover
        endpoint = f"{server_endpoint}:7939"

    session = Boto3SessionProvider(
        endpoint=endpoint,
        role_alias="iot_role_alias",
        # certificate=f"tests/assets/{file_prefix}.pem",
        # private_key=f"tests/assets/{file_prefix}.key",
        certificate=str(cert_file),
        private_key=str(key_file),
        thing_name="my_iot_thing_name",
        ca=ca.cert_pem.bytes(),
        verify_peer=False,
    ).get_session()
    httpserver.expect_request(
        "/role-aliases/iot_role_alias/credentials", method="GET"
    ).respond_with_json(
        {
            "credentials": {
                "accessKeyId": "fake_access_key",
                "secretAccessKey": "fake_secret_key",
                "sessionToken": "fake_session_token",
                "expiration": one_hour_later.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        }
    )
    with pytest.raises(ClientError):
        session.client("sts").get_caller_identity()


def test_invalid_credentials(
    httpserver: pytest_httpserver.HTTPServer,
    ca: trustme.CA,
) -> None:
    """Test call to localhost where response is invalid.

    This will be any non-200 response such as 400, 403, or 404. See dev_details
    for more details.
    """
    if server_endpoint == "::1":  # pragma: no cover
        endpoint = f"[{server_endpoint}]:7939"
    else:  # pragma: no cover
        endpoint = f"{server_endpoint}:7939"
    session = Boto3SessionProvider(
        endpoint=endpoint,
        role_alias="iot_role_alias",
        # certificate=f"tests/assets/{file_prefix}.pem",
        # private_key=f"tests/assets/{file_prefix}.key",
        certificate=str(cert_file),
        private_key=str(key_file),
        thing_name="my_iot_thing_name",
        ca=ca.cert_pem.bytes(),
    ).get_session()
    httpserver.expect_request(
        "/role-aliases/iot_role_alias/credentials", method="GET"
    ).respond_with_json({"message": "Role alias does not exist"}, status=404)
    with pytest.raises(ValueError):
        session.client("sts").get_caller_identity()

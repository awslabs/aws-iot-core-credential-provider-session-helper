"""Test cases for the iot_core_credential_provider module.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

These tests focus on testing the session via files or values for certificates and private keys.
"""
import datetime
import os
import platform
import ssl

import pytest
import pytest_httpserver
import trustme
from awscrt.io import LogLevel
from botocore.exceptions import ClientError

from awsiot_credentialhelper.boto3_session import Boto3SessionProvider


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
    file_prefix = "client_ec256"
else:  # pragma: no cover
    file_prefix = "client_rsa2048"


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
        print("got here")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        # Load the test certificate for mTLS verification
        context.load_verify_locations(cafile=f"tests/assets/{file_prefix}.pem")
    else:  # pragma: no cover
        # macOS and Windows work without server requesting cert
        # context.verify_mode = ssl.CERT_NONE
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    localhost_cert = ca.issue_cert(
        "localhost",
        "127.0.0.1",
        "::1",
    )
    localhost_cert.configure_cert(context)
    return context


def test_get_session_with_files() -> None:
    """Verify session can be created, now with logging!."""
    session = Boto3SessionProvider(
        endpoint="my_endpoint.credentials.iot.us-west-2.amazonaws.com",
        role_alias="iot_role_alias",
        certificate=f"tests/assets/{file_prefix}.pem",
        private_key=f"tests/assets/{file_prefix}.key",
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
    with pytest.raises(ValueError, match="Error completing mTLS connection"):
        Boto3SessionProvider(
            endpoint="cicd_testing.credentials.iot.us-west-2.amazonaws.com",
            role_alias="iot_role_alias",
            certificate=f"tests/assets/{file_prefix}.pem",
            private_key=f"tests/assets/{file_prefix}.key",
            thing_name="my_iot_thing_name",
            # awscrt_log_level=LogLevel.Trace,
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
        certificate=f"tests/assets/{file_prefix}.pem",
        private_key=f"tests/assets/{file_prefix}.key",
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
        certificate=f"tests/assets/{file_prefix}.pem",
        private_key=f"tests/assets/{file_prefix}.key",
        thing_name="my_iot_thing_name",
        ca=ca.cert_pem.bytes(),
    ).get_session()
    httpserver.expect_request(
        "/role-aliases/iot_role_alias/credentials", method="GET"
    ).respond_with_json({"message": "Role alias does not exist"}, status=404)
    with pytest.raises(ValueError):
        session.client("sts").get_caller_identity()

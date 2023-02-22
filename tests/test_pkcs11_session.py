"""Test cases for the iot_core_credential_provider module.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0

These tests focus on the PKCS#11 interface for credentials.
"""
import datetime
import os
import platform
import ssl

import pytest
import pytest_httpserver
import trustme

from aws_iot_core_credential_provider_session_helper.iot_core_credential_provider import (
    IotCoreCredentialProviderSession,
)
from aws_iot_core_credential_provider_session_helper.iot_core_credential_provider import (
    Pkcs11Config,
)


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


@pytest.fixture(scope="session")
def httpserver_listen_address():
    """Return an address for the test HTTP server."""
    return ("localhost", 8888)


@pytest.fixture(scope="session")
def ca():
    """Create CA for mTLS testing."""
    return trustme.CA()


@pytest.fixture(scope="session")
def httpserver_ssl_context(ca):
    """Create an HTTPS server with the CA certificate."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

    # For crypto testing, each OS has difference nuances.
    if os_type == "Linux":  # pragma: no cover
        context.verify_mode = ssl.CERT_REQUIRED
    else:  # pragma: no cover
        # macOS and Windows work without server requesting cert
        context.verify_mode = ssl.CERT_NONE
    # Load the test certificate for mTLS verification
    context.load_verify_locations(cafile="tests/assets/client_rsa2048.pem")
    localhost_cert = ca.issue_cert(
        "localhost",
        "127.0.0.1",
        "::1",
    )
    localhost_cert.configure_cert(context)
    return context


def test_privatekey_pkcs_mutually_excluded() -> None:
    """Private key and pkcs not provided."""
    # verify error is raised when private key and pkcs are NOT provided
    with pytest.raises(
        ValueError,
        match="Private_key or pkcs11 settings must be specified, neither were provided.",
    ):
        IotCoreCredentialProviderSession(
            endpoint="localhost:8888",
            role_alias="iot_role_alias",
            certificate="tests/assets/client_rsa2048.pem",
            thing_name="my_iot_thing_name",
            verify_peer=False,
        ).get_session()

    # verify error is raised when private key and pkcs are BOTH provided
    pkcs11_obj = Pkcs11Config(
        pkcs11_lib="tests/assets/fake_pkcs11_module.so",
        user_pin="1234",
        slot_id=1,
    )
    with pytest.raises(
        ValueError,
        match="Only private_key OR pkcs11 settings must be specified, both were provided.",
    ):
        IotCoreCredentialProviderSession(
            endpoint="localhost:8888",
            role_alias="iot_role_alias",
            certificate="tests/assets/client_rsa2048.pem",
            private_key="tests/assets/client_rsa2048.key",
            thing_name="my_iot_thing_name",
            pkcs11=pkcs11_obj,
        ).get_session()


def test_missing_pkcs_lib() -> None:
    """PKCS#11 library not provided."""
    with pytest.raises(
        ValueError,
        match="PKCS#11 library path must be provided.",
    ):
        IotCoreCredentialProviderSession(
            endpoint="localhost:8888",
            role_alias="iot_role_alias",
            certificate="tests/assets/client_rsa2048.pem",
            thing_name="my_iot_thing_name",
            pkcs11=Pkcs11Config(  # type: ignore
                # pkcs11_lib must be provided - force ignore for mypy
                # pkcs11_lib="tests/assets/fake_pkcs11_module.so",
                user_pin="1234",
                slot_id=1,
            ),
        ).get_session()


def test_invalid_pkcs_lib() -> None:
    """PKCS#11 library not a file."""
    file_path = "tests/assets/not_a_valid_file"
    with pytest.raises(
        ValueError,
        match=f"{file_path} is not a valid file path.",
    ):
        IotCoreCredentialProviderSession(
            endpoint="localhost:8888",
            role_alias="iot_role_alias",
            certificate="tests/assets/client_rsa2048.pem",
            thing_name="my_iot_thing_name",
            pkcs11=Pkcs11Config(
                pkcs11_lib=file_path,
                user_pin="1234",
                slot_id=1,
            ),
        ).get_session()


def test_missing_user_pin() -> None:
    """User pin not provided."""
    IotCoreCredentialProviderSession(
        endpoint="localhost:8888",
        role_alias="iot_role_alias",
        certificate="tests/assets/client_rsa2048.pem",
        thing_name="my_iot_thing_name",
        pkcs11=Pkcs11Config(
            pkcs11_lib="tests/assets/fake_pkcs11_module.so",
            slot_id=1,
        ),
    )


def test_full_pkcs11_config(
    httpserver: pytest_httpserver.HTTPServer,
    ca: trustme.CA,
) -> None:
    """Create and call full PKCS11 config.

    Until a softhsm can be incorporated, no code coverage for
    actual HSM calls, assertion errors only.
    """
    one_hour_later = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

    session = IotCoreCredentialProviderSession(
        endpoint="localhost:8888",
        role_alias="iot_role_alias",
        certificate="tests/assets/client_rsa2048.pem",
        thing_name="my_iot_thing_name",
        pkcs11=Pkcs11Config(  # noqa: S106
            pkcs11_lib="tests/assets/fake_pkcs11_module.so",
            user_pin="1234",
            slot_id=1,
            token_label="test_token",
            private_key_label="test_key_label",
        ),
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
    # create PKCS#11 session to fail due to invalid shared library - expected
    with pytest.raises(RuntimeError, match="AWS_IO_SHARED_LIBRARY_LOAD_FAILURE"):
        session.client("sts").get_caller_identity()

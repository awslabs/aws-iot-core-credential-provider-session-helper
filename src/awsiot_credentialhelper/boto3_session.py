"""Session object classes and methods.

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TypedDict
from typing import cast
from urllib.parse import ParseResult
from urllib.parse import urlparse

from awscrt.exceptions import AwsCrtError
from awscrt.http import HttpClientConnection
from awscrt.http import HttpHeaders
from awscrt.http import HttpRequest
from awscrt.io import ClientBootstrap
from awscrt.io import ClientTlsContext
from awscrt.io import DefaultHostResolver
from awscrt.io import EventLoopGroup
from awscrt.io import LogLevel
from awscrt.io import Pkcs11Lib
from awscrt.io import TlsConnectionOptions
from awscrt.io import TlsContextOptions
from awscrt.io import init_logging
from boto3 import Session
from botocore.credentials import DeferredRefreshableCredentials
from botocore.session import get_session as get_botocore_session
from typing_extensions import NotRequired


logger = logging.getLogger(__name__)


class _IAMBotocoreCredentials(TypedDict):
    """IAM Credentials for Botocore use."""

    access_key: str
    secret_key: str
    token: str
    expiry_time: str


class Pkcs11Config(TypedDict):
    """PKCS11 Configuration for Credential Provider.

    These are needed parameters for the PKCS#11 provider.

    Attributes:
        pkcs11_lib (str): Path to PKCS#11 library on disk.
        user_pin (NotRequired[str]): User pin for PKCS#11 library.
        slot_id (NotRequired[int]): Slot ID for PKCS#11 library. If not provided,
            the ``token_label`` will be used instead.
        token_label (NotRequired[str]): Token label for PKCS#11 library. If not provided,
            the ``slot_id`` will be used instead.
        private_key_label (NotRequired[str]): Label for private key to use.
    """

    pkcs11_lib: str
    user_pin: NotRequired[str]
    slot_id: NotRequired[int]
    token_label: NotRequired[str | None]
    private_key_label: NotRequired[str | None]


class _AwscrtResponse:
    """Holds contents of incoming HTTP response."""

    def __init__(self):
        """Initialize to default for when callbacks are called."""
        self.status_code = None
        self.headers = None
        self.body = bytearray()

    def on_response(self, http_stream, status_code, headers, **kwargs):
        """Process awscrt.io response."""
        self.status_code = status_code  # pragma: no cover
        self.headers = HttpHeaders(headers)  # pragma: no cover

    def on_body(self, http_stream, chunk, **kwargs):
        """Process awscrt.io body."""
        self.body.extend(chunk)  # pragma: no cover


class Boto3SessionProvider:
    """Session object using the AWS IoT Core Credential Provider.

    Creates an object from credentials used to authenticated against the
    AWS IoT Core Credential Provider. After creation, a call to ``get_session()``
    will return a Boto3 session object. That session object will then request
    credentials as needed when Boto3 client calls are issued. The Boto3 session
    object will automatically refresh credentials as they expire.

    Args:
        endpoint: Fully-qualified domain name of the AWS IoT Credential
            Provider endpoint.
        role_alias: IoT Role Alias to use for obtaining the attached IAM Role.
        thing_name: IoT Thing Name attached to the IoT Policy which grants access to
            IoT Role Alias.
        certificate: X.509 certificate registered with AWS IoT Core in PKCS#7
            armored format (e.g., PEM). It can be either a path to the certificate
            on the file system (``str``) *or* the certificate in byte format (``bytes``).
        private_key: Private key associated with the X.509 certificate. It can
            either be a path to the private key on the file system (``str``) *or* the
            private key is byte format (``bytes``).
        pkcs11: Configuration to use a local PKCS#11 interface for private key operations.
        ca: The certificate authority used to validate the AWS IoT Core credential
            provider endpoint. It can either be a path to the certificate authority
            on the file system (``str)`` *or* the certificate authority in byte
            format (``bytes``). Defaults to ``None`` which uses the operating systems default
            trust store.
        awscrt_log_level: Log level for ``awscrt`` operations.
        verify_peer: When set to ``True``, will verify the server certificate against the
            endpoint. Only set to ``False`` for testing purposes. Defaults to ``True``.

    Raises:
        ValueError: Only if ``private_key`` **or** ``pkcs11`` argument are not provided.
    """

    def __init__(
        self,
        endpoint: str,
        role_alias: str,
        thing_name: str,
        certificate: str | bytes,
        private_key: str | bytes | None = None,
        pkcs11: Pkcs11Config | None = None,
        ca: bytes | None = None,
        awscrt_log_level: LogLevel | None = None,
        verify_peer: bool = True,
    ) -> None:
        """Initialize object with AWS IoT Credential Provider details.

        Args:
            endpoint: Fully-qualified domain name of the AWS IoT Credential
                Provider endpoint.
            role_alias: IoT Role Alias to use for obtaining its' attached
                IAM Role.
            thing_name: IoT Thing Name attached to IoT Policy allowed to
                assume role.
            certificate: X.509 certificate registered with AWS IoT Core in PKCS#7
                armored format (e.g., PEM). It can be either a path to the certificate
                on the file system (str) _or_ the certificate in byte format (bytes).
            private_key: Private key associated with the X.509 certificate. It can
                either be a path to the private key on the file system (str) _or_ the
                private key is byte format (bytes).
            pkcs11: Configuration to use PKCS#11 library for private key operations.
            ca: _description_. The certificate authority used to validate the IoT Credential
                Provider endpoint. It can either be a path to the certificate authority
                on the file system (str) _or_ the certificate authority in byte format (bytes).
                Defaults to None.
            awscrt_log_level: Log level for awscrt operations.
            verify_peer: When true, will verify the server certificate against the endpoint.
                Only set to false for testing purposes.

        Raises:
            ValueError: Only ``private_key`` __or__ ``pkcs11`` argument are provided.
        """
        # Set logging level for awscrt if provided, otherwise default of no logging, just assertions
        if awscrt_log_level is not None:
            init_logging(log_level=awscrt_log_level, file_name="stdout")
        else:
            pass

        self._endpoint: str = endpoint
        self._role_alias: str = role_alias
        self._thing_name: str = thing_name
        self._certificate: bytes = self.__load_certificate(certificate)
        self._client_connection_type: str = "mtls"
        self._pkcs11: Pkcs11Config = Pkcs11Config(
            pkcs11_lib="",
        )

        # private key and PKCS mutually exclusive
        if private_key is None and pkcs11 is None:
            raise ValueError(
                "Private_key or pkcs11 settings must be specified, neither were provided."
            )
        if private_key is not None and pkcs11 is not None:
            raise ValueError(
                "Only private_key OR pkcs11 settings must be specified, both were provided."
            )

        # Determine method to create connection (file/value, PKCS#11, Windows credential store)
        if private_key:
            self.__private_key: bytes = self.__load_private_key(
                private_key,
            )
        if pkcs11:
            # Validate and set all values
            self._validate_and_set_pkcs11_config(pkcs11)
            self._client_connection_type = "mtls_pkcs11"

        self.__ca = ca if ca else None
        self.__verify_peer = verify_peer

        # self.__ca: Optional[
        #     bytes
        # ] = ca  # used in testing or to override the default CA trust store

    def get_session(self, **kwargs) -> Session:
        """Create a Boto3 session object with credential refresh using AWS IoT Credential Provider.

        The ``**kwargs`` are passed to the Boto3 session object. The most common use is to set the
        AWS region for the returned sessions object. Any set of `Boto3 session arguments <https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html#boto3.session.Session>`_ can be passed.

        Example:
            >>> from awsiot_credentialhelper.boto3_session import Boto3SessionProvider
            >>> boto3_session = Boto3SessionProvider(
            ...     endpoint="your_endpoint.credentials.iot.us-west-2.amazonaws.com",
            ...     role_alias="your_aws_iot_role_alias_name",
            ...     certificate="iot_thing.pem",
            ...     private_key="iot_thing.pem.key",
            ...     thing_name="iot_thing",
            ... ).get_session(region="eu-central-1") # doctest: +SKIP

        Args:
            **kwargs: Any set of arguments can be passed.

        Returns:
            Session: Boto3 session object tied to IoT Credential Provider for obtaining credentials.
        """  # noqa: B950
        session = get_botocore_session()
        # typing - there is a _session attribute on the Session object
        session._credentials = self._get_refreshable_credentials()  # type: ignore

        # Region extracted from credential provider endpoint
        # Additional validation for unit testing where "localhost" is used
        if len(self._endpoint.split(".")) == 6:  # expected normal FQDN
            session.set_config_variable("region", self._endpoint.split(".")[-3])
        else:  # pytest, set to default (all roads lead to N. Virginia)
            session.set_config_variable("region", "us-east-1")
        # Set any other key-value pairs - for botocore compatibility
        for k, v in kwargs.items():
            session.set_config_variable(k, v)
        return Session(botocore_session=session)

    def _get_refreshable_credentials(self) -> DeferredRefreshableCredentials:
        """Callback for botocore to use the IoT Credential Provider to request credentials.

        Returns:
            Refreshable credentials that will be used by botocore.
        """
        return DeferredRefreshableCredentials(
            method="custom-iot-core-credential-provider",
            refresh_using=self.__get_credentials,
        )

    def _validate_and_set_pkcs11_config(self, pkcs11: Pkcs11Config) -> None:
        """Validate and complete PKCS#11 configuration for private key operations.

        Args:
            pkcs11: Configuration to use PKCS#11 library for private key operations.

        Raises:
            ValueError: A ``Pkcs11Config`` object must be provided, and be a valid file.
        """
        if "pkcs11_lib" not in pkcs11:
            raise ValueError("PKCS#11 library path must be provided.")
        else:
            if Path(pkcs11["pkcs11_lib"]).is_file():
                self._pkcs11["pkcs11_lib"] = pkcs11["pkcs11_lib"]
            else:
                raise ValueError(f"{pkcs11['pkcs11_lib']} is not a valid file path.")
        if "user_pin" in pkcs11:
            self._pkcs11["user_pin"] = pkcs11["user_pin"]
        else:
            # TODO - clarify what value type for user_pin
            # https://awslabs.github.io/aws-crt-python/api/io.html#awscrt.io.TlsContextOptions.create_client_with_mtls_pkcs11 # noqa: B950
            self._pkcs11["user_pin"] = None  # type: ignore
        # The rest of the parameters are optional.
        # The underlying PKCS#11 methods will determine if a single, suitable key is found.
        # TODO: wait for boto3-stubs to be updated for correct typing
        self._pkcs11["slot_id"] = pkcs11["slot_id"] if "slot_id" in pkcs11 else None  # type: ignore
        self._pkcs11["token_label"] = (
            pkcs11["token_label"] if "token_label" in pkcs11 else None
        )
        self._pkcs11["private_key_label"] = (
            pkcs11["private_key_label"] if "private_key_label" in pkcs11 else None
        )
        return

    def __get_credentials(self) -> _IAMBotocoreCredentials:
        """Compute and make the request to IoT Credential Provider endpoint to retrieve IAM Credentials.

        Args: None
        Returns:
            IAMBotocoreCredentials: Credentials acquired from IoT Credential Provider.

            The credentials are returned in a format consumable by botocore to vend to Boto3 sessions:

                {
                    "access_key": accessKeyId,
                    "secret_key": secretAccessKey,
                    "token": sessionToken,
                    "expiry_time": expirationTime,
                }
        """
        return self._mtls_session()

    def _mtls_session(
        self,
    ) -> _IAMBotocoreCredentials:
        """Uses mTLS with provided X.509 certificate/key directly to return IAM credentials.

        This uses the https://awslabs.github.io/aws-crt-python/index.html module for making
        HTTP calls to the IoT Credential provider instead of the Python built-in modules such
        as urllib3, as it provides the ability to use either credentials on file system _or_ as
        a byte stream. This helps reduce the impact of persisting credentials in security
        conscious environments.

        Returns:
            IAM credentials in a format for botocore to use.

        Raises:
            ValueError: Returned error messages, either from connectivity or
                from the IoT Credential Provider. Connectivity messages will
                originate from the ``awscrt`` module and be related with mTLS
                actions. The remainder are responses from the IoT Credential
                Provider.
        """
        url = urlparse(
            f"https://{self._endpoint}/role-aliases/{self._role_alias}/credentials"
        )
        request = HttpRequest("GET", url.path)
        request.headers.add("host", str(url.hostname))
        request.headers.add("x-amzn-iot-thingname", self._thing_name)
        response = _AwscrtResponse()

        # Get port number (used for testing on non-privileged port)
        port = 443 if not url.port else url.port

        # TODO: PKCS#11, Windows certificate store, instructions for macOS
        # Call the mutual TLS method if certificate/key is not PKCS#11

        if self._client_connection_type == "mtls":
            connection = self._mtls_client_connection(
                url=url,
                certificate=self._certificate,
                private_key=self.__private_key,
                port=port,
                ca=self.__ca,
                verify_peer=self.__verify_peer,
            )
        elif self._client_connection_type == "mtls_pkcs11":  # pragma: os-not-linux
            connection = self._mtls_pkcs11_client_connection(
                url=url,
                certificate=self._certificate,
                port=port,
                ca=self.__ca,
                pkcs11=self._pkcs11,
                verify_peer=self.__verify_peer,
            )
        stream = connection.request(request, response.on_response, response.on_body)
        stream.activate()
        stream_completion_result = stream.completion_future.result(10)
        if response.status_code == 200:
            credentials = json.loads(response.body.decode("utf-8"))["credentials"]
            return _IAMBotocoreCredentials(
                access_key=credentials["accessKeyId"],
                secret_key=credentials["secretAccessKey"],
                token=credentials["sessionToken"],
                expiry_time=credentials["expiration"],
            )
        else:
            raise ValueError(
                f"Error {stream_completion_result} getting credentials: {json.loads(response.body.decode())}"
            )

    @staticmethod
    def _mtls_client_connection(
        url: ParseResult,
        certificate: bytes,
        private_key: bytes,
        port: int,
        verify_peer: bool = True,
        ca: bytes | None = None,
    ) -> HttpClientConnection:
        """HTTP client connection using mutual TLS.

        Args:
            url: Full URL to obtain fully-qualified hostname
            certificate: Certificate in PKCS#7 armored (PEM) byte format.
            private_key: Private key in bytes.
            port: Port number to use for HTTPS connection. Default is 443.
            verify_peer: If set to True will verify server certificate against endpoint.
            ca: Certificate authority in bytes. Default is None.


        Returns:
            HttpClientConnection: HTTP client connection.

        Raises:
            ValueError: If the mTLS connection (prior to data transfer) fails to
                be established.
        """
        event_loop_group: EventLoopGroup = EventLoopGroup()
        host_resolver: DefaultHostResolver = DefaultHostResolver(event_loop_group)
        bootstrap: ClientBootstrap = ClientBootstrap(event_loop_group, host_resolver)

        tls_ctx_opt = TlsContextOptions.create_client_with_mtls(
            cert_buffer=certificate, key_buffer=private_key
        )
        if ca:
            tls_ctx_opt.override_default_trust_store(ca)
        tls_ctx_opt.verify_peer = verify_peer
        tls_ctx = ClientTlsContext(tls_ctx_opt)
        tls_conn_opt: TlsConnectionOptions = cast(
            TlsConnectionOptions, tls_ctx.new_connection_options()
        )
        tls_conn_opt.set_server_name(str(url.hostname))

        try:
            connection_future = HttpClientConnection.new(
                host_name=str(url.hostname),
                port=port,
                bootstrap=bootstrap,
                tls_connection_options=tls_conn_opt,
            )
            return connection_future.result(10)
        except AwsCrtError as e:
            raise ValueError(f"Error completing mTLS connection: {e}") from e

    @staticmethod
    def _mtls_pkcs11_client_connection(
        url: ParseResult,
        port: int,
        certificate: bytes,
        pkcs11: Pkcs11Config,
        verify_peer: bool = True,
        ca: bytes | None = None,
    ) -> HttpClientConnection:
        """HTTP client connection using mutual TLS with PKCS#11 for crypto operations.

        Args:
            url: Full URL to obtain fully-qualified hostname
            certificate: Certificate in PKCS#7 armored (PEM) byte format
            port: Port number to use for HTTPS connection. Default is 443.
            pkcs11: PKCS#11 configuration for crypto operations.
            verify_peer: If set to True will verify server certificate against endpoint.
            ca: Certificate authority in bytes. Default is None.

        Returns:
            HttpClientConnection: HTTP client connection

        Raises:
            ValueError: If the mTLS connection (prior to data transfer) fails to
                be established.
        """
        event_loop_group: EventLoopGroup = EventLoopGroup()
        host_resolver: DefaultHostResolver = DefaultHostResolver(event_loop_group)
        bootstrap: ClientBootstrap = ClientBootstrap(event_loop_group, host_resolver)

        tls_ctx_opt = TlsContextOptions.create_client_with_mtls_pkcs11(
            pkcs11_lib=Pkcs11Lib(file=pkcs11["pkcs11_lib"]),
            user_pin=pkcs11["user_pin"],
            slot_id=pkcs11["slot_id"],
            # validation has been completed, copy over values
            # token_label=pkcs11["token_label"] if "token_label" in pkcs11 else None,
            token_label=pkcs11["token_label"],
            private_key_label=pkcs11["private_key_label"],
            cert_file_path=None,
            cert_file_contents=certificate,
        )

        # ###### Coverage exclusion due to some operating systems not supporting PKCS#11
        # ###### and never reaching here.
        if ca:  # pragma: os-not-linux
            tls_ctx_opt.override_default_trust_store(ca)
        tls_ctx_opt.verify_peer = verify_peer  # pragma: os-not-linux
        tls_ctx = ClientTlsContext(tls_ctx_opt)  # pragma: os-not-linux
        tls_conn_opt: TlsConnectionOptions = cast(
            TlsConnectionOptions, tls_ctx.new_connection_options()
        )  # pragma: os-not-linux
        tls_conn_opt.set_server_name(str(url.hostname))  # pragma: os-not-linux
        try:  # pragma: os-not-linux
            connection_future = HttpClientConnection.new(
                host_name=str(url.hostname),
                port=port,
                bootstrap=bootstrap,
                tls_connection_options=tls_conn_opt,
            )
            return connection_future.result(10)
        except AwsCrtError as e:  # pragma: os-not-linux
            raise ValueError(f"Error completing mTLS connection: {e}") from e
        # ###### End coverage exclusion

    @staticmethod
    def __load_certificate(certificate: str | bytes) -> bytes:
        """Load the certificate.

        Args:
            certificate: Representation of the certificate in PEM format.

        Returns:
            bytes: Return certificate in bytes.
        """
        if isinstance(certificate, bytes):
            return certificate
        else:
            with open(Path(certificate), "rb") as cert_pem_file:
                return cert_pem_file.read()

    def __load_private_key(
        self,
        private_key: str | bytes,
    ) -> bytes:
        """Load the private key.

        Args:
            private_key: Representation of the private key in PEM format.

        Returns:
            bytes: Return private key in bytes.
        """
        if isinstance(private_key, bytes):
            return private_key
        else:
            with open(Path(private_key), "rb") as private_key_pem_file:
                return private_key_pem_file.read()

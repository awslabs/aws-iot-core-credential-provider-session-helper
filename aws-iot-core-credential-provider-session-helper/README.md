# AWS IoT Core Credential Provider Session Helper

[![PyPI](https://img.shields.io/pypi/v/iot-core-credential-provider-session-helper.svg)][pypi status]
[![Status](https://img.shields.io/pypi/status/iot-core-credential-provider-session-helper.svg)][pypi status]
[![Python Version](https://img.shields.io/pypi/pyversions/iot-core-credential-provider-session-helper)][pypi status]
[![License](https://img.shields.io/pypi/l/iot-core-credential-provider-session-helper)][license]

[![Tests](https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/workflows/Tests/badge.svg)][tests]

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)][pre-commit]
[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)][black]

[pypi status]: https://pypi.org/project/iot-core-credential-provider-session-helper/
[tests]: https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/actions?workflow=Tests
[pre-commit]: https://github.com/pre-commit/pre-commit
[black]: https://github.com/psf/black

This package provides an easy way to create a **refreshable** boto3 Session using [AWS IoT credential provider](https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html).

## Features

- Automatic refresh of boto3 credentials through requests to the AWS IoT credential provider. No need to manage or maintain refresh times.
- Uses the underlying [AWS CRT Python](https://github.com/awslabs/aws-crt-python) bindings for querying the credential provider instead of the Python standard library. This provides support for both certificate and private keys as files _or_ as environment variables.
- **Future** - Extensible to using other TLS methods such as PKCS#11 hardware security modules.
- Four function calls to create a helper, boto3 session, boto3 client, and then API calls.

## Requirements

- Python 3.8 - 3.11. Support not include for 3.7 as that version will be end of life in June, 2023. If 3.7 support _is_ important, please open an issue to discuss.

## Installation

You can install _AWS IoT Core Credential Provider Session Helper_ via [pip] from [PyPI]:

```console
python3 -m pip install aws-iot-core-credential-provider-session-helper
```

## Usage

Prior to use, ensure all cloud-side resources for IAM and AWS IoT Core have been properly created and configured. Then, with the AWS IoT registered X.509 certificate and corresponding private key (e.g., `iot_thing.pem` and `iot_thing.pem.key`), you can create and use the helper as follows:

```python
import aws_iot_core_credential_provider_session_helper as iotcp_session

# Create helper object (no calls to AWS yet)
helper = iotcp_session.IotCoreCredentialProviderSession(
    endpoint="your_endpoint.credentials.iot.us-west-2.amazonaws.com",
    role_alias="your_aws_iot_role_alias_name",
    certificate="iot_thing.pem",
    private_key="iot_thing.pem.key",
    thing_name="iot_thing",
)

# Create boto3 session object (no calls to AWS yet).
boto3_session = helper.get_session()

# Create an AWS IoT  service client from boto3 session (still no calls to AWS yet)
iot = boto3_session.client("iot")

# Make the first AWS IoT API call. Here is where temporary credentials will be obtained
# and mapped to the session object. The same credentials will be used for all additional
# API calls until they need to be refreshed which will happen automatically.
result = iot.list_things()
```

Please see the [package documentation] for more details and advanced use.

## Contributing

Contributions are very welcome.
To learn more, see the [Contributor Guide].

## License

Distributed under the terms of the [Apache 2.0 license][license].
Details on third party packages used by this package can be found [here][third-party].

## Issues

If you encounter any problems,
please [file an issue] along with a detailed description.

## Credits

This project template was generated from a fork of [@cjolowicz]'s [Hypermodern Python Cookiecutter] template.

[@cjolowicz]: https://github.com/cjolowicz
[pypi]: https://pypi.org/
[hypermodern python cookiecutter]: https://github.com/cjolowicz/cookiecutter-hypermodern-python
[pip]: https://pip.pypa.io/

<!-- github-only -->

[license]: https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/blob/main/LICENSE
[contributor guide]: https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/blob/main/CONTRIBUTING.md
[third-party]: https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/blob/main/THIRD-PARTY-LICENSES.txt
[package-documentation]: https://FQDN_to_doc_site

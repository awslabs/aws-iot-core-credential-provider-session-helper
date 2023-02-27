# AWS IoT Core Credential Provider Session Helper

[![PyPI](https://img.shields.io/pypi/v/awsiot-credentialhelper.svg)][pypi status]
[![Status](https://img.shields.io/pypi/status/awsiot-credentialhelper.svg)][pypi status]
[![Python Version](https://img.shields.io/pypi/pyversions/awsiot-credentialhelper)][pypi status]
[![License](https://img.shields.io/pypi/l/awsiot-credentialhelper)][license]

[![Tests](https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/workflows/Tests/badge.svg)][tests]
[![codecov](https://codecov.io/gh/awslabs/aws-iot-core-credential-provider-session-helper/branch/main/graph/badge.svg?token=8V1XZY37BQ)](https://codecov.io/gh/awslabs/aws-iot-core-credential-provider-session-helper)

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)][pre-commit]
[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)][black]

[pypi status]: https://pypi.org/project/awsiot-credentialhelper/
[tests]: https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/actions?workflow=Tests
[pre-commit]: https://github.com/pre-commit/pre-commit
[black]: https://github.com/psf/black

This package provides an easy way to create a **refreshable** Boto3 Session using the [AWS IoT Core credential provider](https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html).

<p align="center">
<a href="https://awslabs.github.io/aws-iot-core-credential-provider-session-helper/">Package documentation</a>
</p>

## Features

- Automatic refresh of [Boto3 credentials](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html) through requests to the AWS IoT Core credential provider. No need to manage or maintain refresh times.
- Uses the underlying [AWS CRT Python](https://github.com/awslabs/aws-crt-python) bindings for querying the credential provider instead of the Python standard library. This provides support for both certificate and private keys as files _or_ as environment variables.
- Extensible to using other TLS methods such as PKCS#11 hardware security modules (see Advanced section).
- Only requires four function calls to create a session helper, Boto3 session, Boto3 client, and then client API calls.

## Requirements

- Python 3.8 - 3.11. Support not include for 3.7 as that version will be end of life in June, 2023. If 3.7 support _is_ important, please open an issue to discuss.

## Installation

You can install _AWS IoT Core Credential Provider Session Helper_ via [pip] from [PyPI]:

```console
python3 -m pip install awsiot-credentialhelper
```

## Usage

Prior to use, ensure all cloud-side resources for IAM and AWS IoT Core have been properly created and configured. Then, with the AWS IoT registered X.509 certificate and corresponding private key (e.g., `iot_thing.pem` and `iot_thing.pem.key`), you can create and use the helper as follows:

```python
from awsiot_credentialhelper.boto3_session import Boto3SessionProvider

# Create boto3 session object
boto3_session = Boto3SessionProvider(
    endpoint="your_endpoint.credentials.iot.us-west-2.amazonaws.com",
    role_alias="your_aws_iot_role_alias_name",
    certificate="iot_thing.pem",
    private_key="iot_thing.pem.key",
    thing_name="iot_thing",
).get_session()

# Use in regular Boto3 chained operations, such as returning caller identity
print(boto3_session.client("sts").get_caller_identity())
{'UserId': 'AROA...F3D:4686c...0a0d', 'Account': '1234567890', 'Arn': 'arn:aws:sts::1234567890:assumed-role/iam_role_name/4686c...0a0d', 'ResponseMetadata': {'RequestId': 'cc04...10bc', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': 'cc04...10bc', 'content-type': 'text/xml', 'content-length': '554', 'date': 'Tue, 21 Feb 2023 21:18:23 GMT'}, 'RetryAttempts': 0}}

# Or by creating a service client and making API calls
iot = boto3_session.client("iot")
result = iot.list_things()
```

Please see the [package documentation](https://awslabs.github.io/aws-iot-core-credential-provider-session-helper/) for more details and advanced use.

## Contributing

Contributions are very welcome.
To learn more, see the [Contributor Guide].

## License

Distributed under the terms of the [Apache 2.0 license][license].
Details on third party packages used by this package can be found [here](https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/blob/main/THIRD-PARTY-LICENSES.txt).

## Issues

If you encounter any problems, please [file an issue](https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/issues/new) along with a detailed description.

## Credits

This project template was generated from a fork of [@cjolowicz]'s [Hypermodern Python Cookiecutter] template.

[@cjolowicz]: https://github.com/cjolowicz
[pypi]: https://pypi.org/
[hypermodern python cookiecutter]: https://github.com/cjolowicz/cookiecutter-hypermodern-python
[pip]: https://pip.pypa.io/

<!-- github-only -->

[license]: https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/blob/main/LICENSE
[contributor guide]: https://github.com/awslabs/aws-iot-core-credential-provider-session-helper/blob/main/CONTRIBUTING.md

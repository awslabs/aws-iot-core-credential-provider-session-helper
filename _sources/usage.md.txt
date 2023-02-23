# Usage

This section covers the most common usage patterns for the helper, plus details on all the parameters that can be passed to build a Boto3 session object. It also covers less common uses such as PKCS#11 or the use of credentials from environment variables.

## General usage

The most common use of the helper is through the use of local credentials stored on disk. This is the least recommended approach unless the private key file is properly protected from accidental or malicious use. For the example below, the credentials are stored in `/home/iotuser/.credentials`, and the application code has access to them.

This walks through the steps to create and use the helper.

```python
# 1. Shorten the name of the session helper class
from awscrt.io import LogLevel
from awsiot_credentialhelper.boto3_session import Boto3SessionProvider

# 2. Create boto3 session object, endpoint name must match the AWS accounts unique
#    credential provider endpoint if using certificates registered without a
#    certificate authority. The get_session can also be passed a specific region other
#    than the region where credentials are obtained.
boto3_session = Boto3SessionProvider(
    endpoint="your_endpoint.credentials.iot.us-west-2.amazonaws.com",
    role_alias="your_aws_iot_role_alias_name",
    certificate="/home/iotuser/.credentials/iot_thing.pem",
    private_key="/home/iotuser/.credentials/iot_thing.pem.key",
    thing_name="iot_thing",
    # The rest are optional parameters, normally reserved for testing.
    # This CA is used to verify the credential provider endpoint's server certificate.
    ca="/opt/certs/AmazonCA1.pem",
    # Enable logging for the awscrt package, from NoLogs to Trace.
    awscrt_log_level=LogLevel.Debug,
    # When set to False removes the verification of the server certificate name to the endpoint
    verify_peer=True,
).get_session(region="us-east-1")

# 3. With the session created, the helper will automatically request, cache, and refresh AWS credentials
#    based on the duration set with the IoT Role Alias (15 minutes to 12 hours).

# Creation of a client object doesn't make a network call to requests credentials
iot = boto3_session.client("iot")

# The first actual API call return credentials, cache them, and use the for all subsequent calls until
# the near expiration, at which time the helper will automatically refresh them.
result = iot.list_things()
...
# 5 minutes pass. This next call uses the same credentials
result = iot_list_things()
...
# 14 hours pass. This call will see the credentials have expired, so before the call the helper
# will request and cache new credentials
result = iot_list_things()
```

## Credentials as environment variables

In certain situations, it may be more suitable provide the application credentials as variable and not give the application direct access to the credentials on disk. An example of this may be Python code running within in isolated environment such as a container.

By passing the certificate and private key as `bytes`, the helper will work as expected. Assume that the credentials are available as `CERTIFICATE_PEM` and `PRIVATE_KEY_PEM` environment variables. The values are read, encoded into [UTF-8](https://en.wikipedia.org/wiki/UTF-8), and then encoded as `bytes`. These will be used in the same manner as reading the certificate or private key from disk.

```python
import os
from awsiot_credentialhelper.boto3_session import Boto3SessionProvider

boto3_session = Boto3SessionProvider(
    endpoint="your_endpoint.credentials.iot.us-west-2.amazonaws.com",
    role_alias="your_aws_iot_role_alias_name",
    certificate=bytes(os.environ["CERTIFICATE_PEM"].encode("utf-8")),
    private_key=bytes(os.environ["PRIVATE_KEY_PEM"].encode("utf-8")),
    thing_name="iot_thing",
).get_session()
```

These can also be mixed. For instance the certificate can be passed as file and the private key as a byte array:

```python
...
boto3_session = Boto3SessionProvider(
    endpoint="your_endpoint.credentials.iot.us-west-2.amazonaws.com",
    role_alias="your_aws_iot_role_alias_name",
    certificate="/home/iotuser/.credentials/iot_thing.pem",
    private_key=bytes(os.environ["PRIVATE_KEY_PEM"].encode("utf-8")),
    thing_name="iot_thing",
).get_session()
```

To use this with containers, the values can be read and passed by the orchestrator (e.g., AWS IoT Greengrass, Kubernetes) as part of a `docker run` command like this:

```shell
$ CERTIFICATE_PEM="some string" PRIVATE_KEY_PEM="some string" docker run -it -rm image_name ...
```

The provided `CERTIFICATE_PEM` and `PRIVATE_KEY_PEM` will be accessible as environment variables within the running container's context.

## Using PKCS#11 with the helper

By using the awscrt package, the helper can also be used where it has _no_ access to the private key except through a hardware security module (HSM). By offloading all crypto operations (encryption and decryption) to the HSM, this reduces the attack surface in obtaining the private key.

However, there are some caveats:

- The PKCS#11 interface is only available on Unix (Linux) operating systems--it is not available for Windows or macOS.
- You are responsible for obtaining the library to interface with the specific HSM from the vendor.
- The X.509 certificate must be present on disk (or as a variable--see above), and cannot be referenced from with the HSM.

Instead of provide the `private_key` parameter, a `pkcs11` configuration is provided. The example below expects the private key to be located in slot 1 _or_ have the defined `token_label`, and the private key is labeled with `test_key`. The `user_pin` is used to access the HSM. The steps to evaluate the private key are complex, please see the [awscrt io documentation](https://awslabs.github.io/aws-crt-python/api/io.html#awscrt.io.TlsContextOptions.create_client_with_mtls_pkcs11) for more details.

```python
from awsiot_credentialhelper.boto3_session import (
    Boto3SessionProvider,
)
from awsiot_credentialhelper.boto3_session import (
    Pkcs11Config,
)

boto3_session = Boto3SessionProvider(
    endpoint="your_endpoint.credentials.iot.us-west-2.amazonaws.com",
    role_alias="your_aws_iot_role_alias_name",
    certificate="/home/iotuser/.credentials/iot_thing.pem",
    thing_name="iot_thing",
    pkcs11=Pkcs11Config(
        pkcs11_lib="/path/to/vendor/provided/module/pkcs11_module.so",
        user_pin="1234",
        slot_id=1,
        token_label="my_token_label",
        private_key_label="test_key",
    ),
).get_session()
```

After this, the `boto3_session` object can used as in the previous examples.

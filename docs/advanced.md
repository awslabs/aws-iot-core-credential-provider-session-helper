# Advanced usage

In this section, more complex uses of the session helper are described. All examples and walkthroughs will be categorized and be referable from the menu to the right.

## Protecting credentials

One main tenet for devices or users outside of our control is to reduce the attack surface if or when the device is compromised. These uses cover different scenarios.

### PKCS#11 on Canonical Ubuntu walkthrough

This walkthrough demonstrated how to use the session helper with SoftHSM. It covers how to use a private key stored within a PKCS#11 environment.

#### Prerequisites

- AWS IoT Role Alias configured with thing, certificate, and AWS IoT policy
- A registered X.509 certificate and corresponding private key
- An Ubuntu desktop or server environment with sudo access - the walkthrough uses Ubuntu 22.04.1 LTS
- Python with the `awsiot-credentialhelper` installed

#### Steps

1. Login to the Ubuntu system (host system) and start a command line interface.

1. Create a directory and copy the certificate and private key there

   ```shell
   $ mkdir $HOME/hsm_test
   $ cd $HOME/hsm_test
   $ cp /path/to/certificate thing-cert.pem
   $ cp /path/to/private-key thing-key.pem
   ```

1. Install dependencies, SoftHSM2, initialize and record slot number

   ```shell
   $ sudo apt update && sudo apt install -y softhsm2 pcregrep opensc gnutls-bin
   $ mkdir -p $HOME/lib/softhsm/tokens
   $ cd $HOME/lib/softhsm/
   $ echo "directories.tokendir = $PWD/tokens" > softhsm2.conf
   $ export SOFTHSM2_CONF=$HOME/lib/softhsm/softhsm2.conf
   $ cd $HOME/hsm_test
   $ echo $(softhsm2-util --init-token --free \
     --so-pin 1234 --pin 1234 --label hsm_thing|pcregrep -o1 \
     '.* to slot (.*)') > slot.txt
   ```

1. Verify the private key is in PKCS#8 format. This the first major challenge in getting keys into the right format. SoftHSM2 will alert if the key is not in the correct format.

   ```shell
   $ # Covert PCKS#1 (--BEGIN RSA PRIVATE KEY--) to PKCS#8 (--BEGIN PRIVATE KEY--)
   $ mv thing-key.pem thing-key-pkcs1.pem
   $ openssl pkcs8 -in thing-key-pkcs1.pem -topk8 -nocrypt -out thing-key.pem
   ```

1. Import the private key into newly initialized slot and verify content.

   ```shell
   $ softhsm2-util --import thing-key.pem --slot $(cat slot.txt) --label hsm_thing_key \
   --id 0000 --pin 1234
   The key pair has been imported.
   $ p11-tool --list-tokens
    Token 0:
        URL: pkcs11:model=p11-kit-trust;manufacturer=PKCS%2311%20Kit;serial=1;token=System%20Trust
        Label: System Trust
        Type: Trust module
        Flags: uPIN uninitialized
        Manufacturer: PKCS#11 Kit
        Model: p11-kit-trust
        Serial: 1
        Module: p11-kit-trust.so


    Token 1:
        URL: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=050524a5fd9dec1d;token=hsm_thing
        Label: hsm_thing
        Type: Generic token
        Flags: RNG, Requires login
        Manufacturer: SoftHSM project
        Model: SoftHSM v2
        Serial: 050524a5fd9dec1d
        Module: /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
   ```

1. Create a Python file with the follow code (`pkcs11.py`), replacing the `endpoint`, `role_alias`, and `thing_name` values. The `pkcs11` entry uses values for the imported key.

   ```python
   from awsiot_credentialhelper.boto3_session import (
       Boto3SessionProvider,
   )
   from awsiot_credentialhelper.boto3_session import (
       Pkcs11Config,
   )
   # from awscrt.io import LogLevel

   boto3_session = Boto3SessionProvider(
       endpoint="YOUR_ENDPOINT.credentials.iot.REGION.amazonaws.com",
       role_alias="YOUR_ROLE_ALIAS",
       certificate="thing-cert.pem",
       thing_name="YOUR_THING_NAME",
       pkcs11=Pkcs11Config(
           pkcs11_lib="/usr/lib/softhsm/libsofthsm2.so",
           user_pin="1234",
           token_label="hsm_thing",
           private_key_label="hsm_thing_key",
       ),
       # awscrt_log_level=LogLevel.Trace,
   ).get_session()
   print(boto3_session.client("sts").get_caller_identity())
   ```

1. Test the code by running and verifying a response.

   ```shell
   $ python3 pkcs11.py
   {'UserId': 'AROA...F3D:4686...0a0d', 'Account': '1234567890', 'Arn': 'arn:aws:sts::1234567890:assumed-role/test_iot_role_alias/4686...0a0d', 'ResponseMetadata': {'RequestId': 'd6598737-9b63-4dd2-a0d3-cdf3a719bb39', 'HTTPStatusCode': 200, 'HTTPHeaders': {'x-amzn-requestid': 'd6598737-9b63-4dd2-a0d3-cdf3a719bb39', 'content-type': 'text/xml', 'content-length': '554', 'date': 'Fri, 24 Feb 2023 23:36:50 GMT'}, 'RetryAttempts': 0}}
   ```

That confirms that the session helper used the SoftHSM2 to perform the cryptographic operations. This walkthrough doesn't cover the nuances of PKCS#11--there are many! However, if you uncomment the `from awscrt.io` and `awscrt_log_level` lines, this will provide details on what the awscrt runtime is doing.

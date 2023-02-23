"""Code to exercise the PKCS#11 interface.

This code is intended to be run as a test case within a Linux environment.
"""
from os import environ

import awsiot_credentialhelper.boto3_session as iotcp
from awsiot_credentialhelper.boto3_session import Pkcs11Config


SLOT_ID = str(environ.get("SLOT_ID"))

session = iotcp.Boto3SessionProvider(
    endpoint="invalid_test_endpoint.credentials.iot.us-west-2.amazonaws.com",
    role_alias="test_role_alias",
    certificate="hsm_thing-cert.pem",
    pkcs11=Pkcs11Config(
        pkcs11_lib="/usr/lib/softhsm/libsofthsm2.so",
        user_pin="1234",
        slot_id=int(SLOT_ID),
        private_key_label="hsm_thing_key",
    ),
    thing_name="hsm_thing1",
).get_session()

session.client("sts").get_caller_identity()

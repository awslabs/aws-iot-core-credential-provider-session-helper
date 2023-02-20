# Things of interest during development

## Credential Provider responses

To determine what exceptions to raise, the following are the various scenarios and responses from the credential provider. All tests with invalid certificates don't exercise all of these conditions, so the potentially known interactions with resources were exercised and documented. What was not tested was the use of an invalid certificate (e.g., one not registered with AWS IoT Core). In those cases, the underlying `awscrt` raised errors were passed back to the calling function.

All tests assume a valid certificate and key registered with IoT Core. A ✅ indicates the proper association of the certificate with the other resources, while a ❌ means that is doesn't. Further tests use the same ✅ / ❌ to delineate association of other resources.

For each test, the following were used:

- IoT Policy - `test_iot_policy` (with and without credential allowed for permissions)
- IoT Role Alias - `test_role_alias`
- IAM Role - `test_iot_role_alias` (permissions are managed role for IoT Readonly)

The curl command used:

```shell
$ curl -v --cert thing1.pem --key thing1.key -H "x-amzn-iot-thingname: thing1" --cacert AmazonRootCA1.pem https://account_endpoint.credentials.iot.us-west-2.amazonaws.com/role-aliases/test_role_alias/credentials
*   Trying 35.160.122.23:443...
* Connected to account_endpoint.credentials.iot.us-west-2.amazonaws.com (35.160.122.23) port 443 (#0)
* ALPN: offers h2
* ALPN: offers http/1.1
*  CAfile: AmazonRootCA1.pem
*  CApath: none
* (304) (OUT), TLS handshake, Client hello (1):
* (304) (IN), TLS handshake, Server hello (2):
...
< x-amzn-RequestId: 36ecd80d-bfc4-c9d0-0871-6bec7744a237
< x-amzn-ErrorType: AccessDeniedException
<
* Connection #0 to host account_endpoint.credentials.iot.us-west-2.amazonaws.com left intact
{"message":"Certificate is invalid on this endpoint"}%
```

The final line, which is the JSON payload of the body response was mapped with the status code.

Then for each combination of resources:

| Thing | IoT Policy | IoT Policy Permissions | IoT Role Alias | IAM Role | Role Alias Duration <= IAM Role | Status Code | Response Body                                                                                                                 |
| :---: | :--------: | :--------------------: | :------------: | :------: | :-----------------------------: | :---------: | ----------------------------------------------------------------------------------------------------------------------------- |
|  ❌   |     ❌     |           ❌           |       ❌       |    ❌    |               ❌                |     403     | `{"message":"Invalid thing name passed"}`                                                                                     |
|  ❌   |     ✅     |           ❌           |       ❌       |    ❌    |               ❌                |     403     | `{"message":"Invalid thing name passed"}`                                                                                     |
|  ✅   |     ✅     |           ❌           |       ❌       |    ❌    |               ❌                |     403     | `{"message":"Access Denied"}`                                                                                                 |
|  ✅   |     ✅     |           ✅           |       ❌       |    ❌    |               ❌                |     404     | `{"message":"Role alias does not exist"}`                                                                                     |
|  ✅   |     ✅     |           ✅           |       ✅       |    ❌    |               ❌                |     400     | `{"message":"Unable to assume the role, or the role to assume does not exist"}`                                               |
|  ✅   |     ✅     |           ✅           |       ✅       |    ✅    |               ❌                |     400     | `{"message":"The requested CredentialDurationSeconds exceeds the MaxSessionDuration set for the role"}`                       |
|  ✅   |     ✅     |           ✅           |       ✅       |    ✅    |               ✅                |     200     | `{"credentials":{"accessKeyId":"A..4","secretAccessKey":"0..h","sessionToken":"I..Q==","expiration":"2023-02-06T05:54:46Z"}}` |

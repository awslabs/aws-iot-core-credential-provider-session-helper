# Testing using private key stored in SoftHSM

**Do not use SoftHSM in production. This is example is to test and validate using the [SoftHSM](https://github.com/opendnssec/SoftHSMv2) for testing and code build processes**

SoftHSM provides a way to test the PKCS#11 interface to the AWS IoT Credential Provider Session Helper. Only use in non-production accounts and consider all keys and certificates to be vulnerable and not-secure.

## Install SoftHSM

Notes on testing with SoftHSM. Operating system specific instructions provided.

### macOS

Use [Homebrew](https://brew.sh/) to install the needed packages:

```shell
brew install softhsm pkcs11-tools libp11 opensc openssl@3 p11-kit
```

**NOTE:** `openssl@3` is needed as the PKCS#11 library provided by `libp11` is compiled against that. To keep things from messing up the local environment, for OpenSSl commands, use the following:

```shell
OPENSSL_CONF=hsm.conf /usr/local/opt/openssl@3/bin/openssl ... (rest of command)
```

To create self-signed cert, using [this post](https://github.com/mylamour/blog/issues/80) as the basis.

Start new shell for path to pick up new commands.

#### Setup environment and create CA key pairs

1. Change to working directory (`~/hsm`) for this example, then create the folders used by OpenSSL.

   ```shell
   cd ~/hsm
   mkdir certs private crl csr newcerts
   chmod 400 private
   touch index.txt
   echo 1000 > serial
   ```

1. Initial a softhsm2 slot and generate CA keys

   ```shell
   # It will ask for SO and User PIN, used 1234 for both
   softhsm2-util --init-token --slot 0 --label myca
   pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -l --keypairgen --key-type EC:secp384r1 --id 01 --label "SSL Root CA 01"
   pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -l --keypairgen --key-type EC:secp384r1 --id 02 --label "SSL Issue CA 01"
   ```

1. Get the slot id associated with `myca`, then create local `~/hsm/hsm.conf` OpenSSL file with that slot number from this template. This is basically the PKCS#11 init followed by the default `/usr/local/etc/openssl@3/openssl.cnf` file contents.

   ```conf
   # PKCS11 engine config
   openssl_conf = openssl_init

   [openssl_init]
   engines = engine_section

   [engine_section]
   pkcs11 = pkcs11_section

   [pkcs11_section]
   engine_id = pkcs11
   dynamic_path = /usr/local/Cellar/libp11/0.4.12/lib/engines-1.1/pkcs11.dylib
   MODULE_PATH = /usr/local/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so
   init = numberfromabovecommand

   #
   # OpenSSL example configuration file.
   HOME                    = .

   # Comment out the next line to ignore configuration errors
   config_diagnostics = 1

   # Extra OBJECT IDENTIFIER info:
   # oid_file       = $ENV::HOME/.oid
   oid_section = new_oids

   # To use this configuration file with the "-extfile" option of the
   # "openssl x509" utility, name here the section containing the
   # X.509v3 extensions to use:
   # extensions            =
   # (Alternatively, use a configuration file that has only
   # X.509v3 extensions in its main [= default] section.)

   [ new_oids ]
   # We can add new OIDs in here for use by 'ca', 'req' and 'ts'.
   # Add a simple OID like this:
   # testoid1=1.2.3.4
   # Or use config file substitution like this:
   # testoid2=${testoid1}.5.6

   # Policies used by the TSA examples.
   tsa_policy1 = 1.2.3.4.1
   tsa_policy2 = 1.2.3.4.5.6
   tsa_policy3 = 1.2.3.4.5.7

   # For FIPS
   # Optionally include a file that is generated by the OpenSSL fipsinstall
   # application. This file contains configuration data required by the OpenSSL
   # fips provider. It contains a named section e.g. [fips_sect] which is
   # referenced from the [provider_sect] below.
   # Refer to the OpenSSL security policy for more information.
   # .include fipsmodule.cnf

   [default_sect]
   # activate = 1


   ####################################################################
   [ ca ]
   default_ca      = CA_default            # The default ca section

   ####################################################################
   [ CA_default ]

   dir             = .                     # Where everything is kept
   certs           = $dir/certs            # Where the issued certs are kept
   crl_dir         = $dir/crl              # Where the issued crl are kept
   database        = $dir/index.txt        # database index file.
   #unique_subject = no                    # Set to 'no' to allow creation of
                                           # several certs with same subject.
   new_certs_dir   = $dir/newcerts         # default place for new certs.

   certificate     = $dir/certs/root.ca.cert.pem  # The CA certificate
   serial          = $dir/serial           # The current serial number
   crlnumber       = $dir/crlnumber        # the current crl number
                                           # must be commented out to leave a V1 CRL
   crl             = $dir/crl.pem          # The current CRL
   private_key     = $dir/private/cakey.pem# The private key

   x509_extensions = usr_cert              # The extensions to add to the cert

   # Comment out the following two lines for the "traditional"
   # (and highly broken) format.
   name_opt        = ca_default            # Subject Name options
   cert_opt        = ca_default            # Certificate field options

   # Extension copying option: use with caution.
   # copy_extensions = copy

   # Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
   # so this is commented out by default to leave a V1 CRL.
   # crlnumber must also be commented out to leave a V1 CRL.
   # crl_extensions        = crl_ext

   default_days    = 365                   # how long to certify for
   default_crl_days= 30                    # how long before next CRL
   default_md      = default               # use public key default MD
   preserve        = no                    # keep passed DN ordering

   # A few difference way of specifying how similar the request should look
   # For type CA, the listed attributes must be the same, and the optional
   # and supplied fields are just that :-)
   policy          = policy_match

   # For the CA policy
   [ policy_match ]
   countryName             = match
   stateOrProvinceName     = match
   organizationName        = match
   organizationalUnitName  = optional
   commonName              = supplied
   emailAddress            = optional

   # For the 'anything' policy
   # At this point in time, you must list all acceptable 'object'
   # types.
   [ policy_anything ]
   countryName             = optional
   stateOrProvinceName     = optional
   localityName            = optional
   organizationName        = optional
   organizationalUnitName  = optional
   commonName              = supplied
   emailAddress            = optional

   ####################################################################
   [ req ]
   default_bits            = 2048
   default_keyfile         = privkey.pem
   distinguished_name      = req_distinguished_name
   attributes              = req_attributes
   x509_extensions = v3_ca # The extensions to add to the self signed cert

   # Passwords for private keys if not present they will be prompted for
   # input_password = secret
   # output_password = secret

   # This sets a mask for permitted string types. There are several options.
   # default: PrintableString, T61String, BMPString.
   # pkix   : PrintableString, BMPString (PKIX recommendation before 2004)
   # utf8only: only UTF8Strings (PKIX recommendation after 2004).
   # nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
   # MASK:XXXX a literal mask value.
   # WARNING: ancient versions of Netscape crash on BMPStrings or UTF8Strings.
   string_mask = utf8only

   # req_extensions = v3_req # The extensions to add to a certificate request

   [ req_distinguished_name ]
   countryName                     = Country Name (2 letter code)
   countryName_default             = AU
   countryName_min                 = 2
   countryName_max                 = 2

   stateOrProvinceName             = State or Province Name (full name)
   stateOrProvinceName_default     = Some-State

   localityName                    = Locality Name (eg, city)

   0.organizationName              = Organization Name (eg, company)
   0.organizationName_default      = Internet Widgits Pty Ltd

   # we can do this but it is not needed normally :-)
   #1.organizationName             = Second Organization Name (eg, company)
   #1.organizationName_default     = World Wide Web Pty Ltd

   organizationalUnitName          = Organizational Unit Name (eg, section)
   #organizationalUnitName_default =

   commonName                      = Common Name (e.g. server FQDN or YOUR name)
   commonName_max                  = 64

   emailAddress                    = Email Address
   emailAddress_max                = 64

   # SET-ex3                       = SET extension number 3

   [ req_attributes ]
   challengePassword               = A challenge password
   challengePassword_min           = 4
   challengePassword_max           = 20

   unstructuredName                = An optional company name

   [ usr_cert ]

   # These extensions are added when 'ca' signs a request.

   # This goes against PKIX guidelines but some CAs do it and some software
   # requires this to avoid interpreting an end user certificate as a CA.

   basicConstraints=CA:FALSE

   # This is typical in keyUsage for a client certificate.
   # keyUsage = nonRepudiation, digitalSignature, keyEncipherment
   keyUsage = digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment
   # PKIX recommendations harmless if included in all certificates.
   subjectKeyIdentifier=hash
   authorityKeyIdentifier=keyid,issuer

   # This stuff is for subjectAltName and issuerAltname.
   # Import the email address.
   # subjectAltName=email:copy
   # An alternative to produce certificates that aren't
   # deprecated according to PKIX.
   # subjectAltName=email:move

   # Copy subject details
   # issuerAltName=issuer:copy

   # This is required for TSA certificates.
   # extendedKeyUsage = critical,timeStamping

   [ v3_req ]
   # Extensions to add to a certificate request
   basicConstraints = CA:FALSE
   keyUsage = nonRepudiation, digitalSignature, keyEncipherment

   [ v3_ca ]
   # Extensions for a typical CA
   # PKIX recommendation.
   subjectKeyIdentifier=hash
   authorityKeyIdentifier=keyid:always,issuer
   basicConstraints = critical,CA:true

   # Key usage: this is typical for a CA certificate. However since it will
   # prevent it being used as an test self-signed certificate it is best
   # left out by default.
   # keyUsage = cRLSign, keyCertSign

   # Include email address in subject alt name: another PKIX recommendation
   # subjectAltName=email:copy
   # Copy issuer details
   # issuerAltName=issuer:copy

   # DER hex encoding of an extension: beware experts only!
   # obj=DER:02:03
   # Where 'obj' is a standard or added object
   # You can even override a supported extension:
   # basicConstraints= critical, DER:30:03:01:01:FF

   [v3_intermediate_ca]
   # Extensions for a typical intermediate CA (`man x509v3_config`).
   subjectKeyIdentifier = hash
   authorityKeyIdentifier = keyid:always,issuer
   basicConstraints = critical, CA:true, pathlen:0
   keyUsage = critical, digitalSignature, cRLSign, keyCertSign

   [ crl_ext ]
   # CRL extensions.
   # Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.
   # issuerAltName=issuer:copy
   authorityKeyIdentifier=keyid:always

   [ proxy_cert_ext ]
   # These extensions should be added when creating a proxy certificate

   # This goes against PKIX guidelines but some CAs do it and some software
   # requires this to avoid interpreting an end user certificate as a CA.

   basicConstraints=CA:FALSE

   # This is typical in keyUsage for a client certificate.
   # keyUsage = nonRepudiation, digitalSignature, keyEncipherment

   # PKIX recommendations harmless if included in all certificates.
   subjectKeyIdentifier=hash
   authorityKeyIdentifier=keyid,issuer

   # This stuff is for subjectAltName and issuerAltname.
   # Import the email address.
   # subjectAltName=email:copy
   # An alternative to produce certificates that aren't
   # deprecated according to PKIX.
   # subjectAltName=email:move

   # Copy subject details
   # issuerAltName=issuer:copy

   # This really needs to be in place for it to be a proxy certificate.
   proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

   ####################################################################
   [ tsa ]

   default_tsa = tsa_config1       # the default TSA section

   [ tsa_config1 ]

   # These are used by the TSA reply generation only.
   dir             = .                     # TSA root directory
   serial          = $dir/tsaserial        # The current serial number (mandatory)
   crypto_device   = builtin               # OpenSSL engine to use for signing
   signer_cert     = $dir/tsacert.pem      # The TSA signing certificate
                                           # (optional)
   certs           = $dir/cacert.pem       # Certificate chain to include in reply
                                           # (optional)
   signer_key      = $dir/private/tsakey.pem # The TSA private key (optional)
   signer_digest  = sha256                 # Signing digest to use. (Optional)
   default_policy  = tsa_policy1           # Policy if request did not specify it
                                           # (optional)
   other_policies  = tsa_policy2, tsa_policy3      # acceptable policies (optional)
   digests     = sha1, sha256, sha384, sha512  # Acceptable message digests (mandatory)
   accuracy        = secs:1, millisecs:500, microsecs:100  # (optional)
   clock_precision_digits  = 0     # number of digits after dot. (optional)
   ordering                = yes   # Is ordering defined for timestamps?
                                   # (optional, default: no)
   tsa_name                = yes   # Must the TSA name be included in the reply?
                                   # (optional, default: no)
   ess_cert_id_chain       = no    # Must the ESS cert id chain be included?
                                   # (optional, default: no)
   ess_cert_id_alg         = sha1  # algorithm to compute certificate
                                   # identifier (optional, default: sha1)

   [insta] # CMP using Insta Demo CA
   # Message transfer
   server = pki.certificate.fi:8700
   # proxy = # set this as far as needed, e.g., http://192.168.1.1:8080
   # tls_use = 0
   path = pkix/

   # Server authentication
   recipient = "/C=FI/O=Insta Demo/CN=Insta Demo CA" # or set srvcert or issuer
   ignore_keyusage = 1 # potentially needed quirk
   unprotected_errors = 1 # potentially needed quirk
   extracertsout = insta.extracerts.pem

   # Client authentication
   ref = 3078 # user identification
   secret = pass:insta # can be used for both client and server side

   # Generic message options
   cmd = ir # default operation, can be overridden on cmd line with, e.g., kur

   # Certificate enrollment
   subject = "/CN=openssl-cmp-test"
   newkey = insta.priv.pem
   out_trusted = insta.ca.crt
   certout = insta.cert.pem

   [pbm] # Password-based protection for Insta CA
   # Server and client authentication
   ref = $insta::ref # 3078
   secret = $insta::secret # pass:insta

   [signature] # Signature-based protection for Insta CA
   # Server authentication
   trusted = insta.ca.crt # does not include keyUsage digitalSignature

   # Client authentication
   secret = # disable PBM
   key = $insta::newkey # insta.priv.pem
   cert = $insta::certout # insta.cert.pem

   [ir]
   cmd = ir

   [cr]
   cmd = cr

   [kur]
   # Certificate update
   cmd = kur
   oldcert = $insta::certout # insta.cert.pem

   [rr]
   # Certificate revocation
   cmd = rr
   oldcert = $insta::certout # insta.cert.pem
   ```

#### Create CA certificates

1. Create root CA using id=01.

   ```shell
   $ OPENSSL_CONF=hsm.conf /usr/local/opt/openssl@3/bin/openssl req -new -x509 -days 7300 -sha512 -extensions v3_ca  -engine pkcs11 -keyform engine -key REPLACE_WITH_SLOT_NUMBER:01

   Engine "pkcs11" set.
   Enter PKCS#11 token PIN for myca:
   You are about to be asked to enter information that will be incorporated
   into your certificate request.
   What you are about to enter is what is called a Distinguished Name or a DN.
   There are quite a few fields but you can leave some blank
   For some fields there will be a default value,
   If you enter '.', the field will be left blank.
   -----
   Country Name (2 letter code) [AU]:US
   State or Province Name (full name) [Some-State]:Colorado
   Locality Name (eg, city) []:Denver
   Organization Name (eg, company) [Internet Widgits Pty Ltd]:HSM Test
   Organizational Unit Name (eg, section) []:Testing
   Common Name (e.g. server FQDN or YOUR name) []:SPKI SSL ROOT CA 01
   Email Address []:not_needed
   ```

1. Verify cert (normal OpenSSL can be used for this 😄):

   ```shell
   $ openssl x509 -in certs/root.ca.cert.pem -noout -text
   Certificate:
       Data:
           Version: 3 (0x2)
           Serial Number:
               5e:4e:c8:c6:f2:a4:95:be:eb:62:3d:19:af:cd:de:91:3d:56:80:44
           Signature Algorithm: ecdsa-with-SHA512
           Issuer: C = US, ST = Colorado, L = Denver, O = HSM Test, OU = Testing, CN = SPKI SSL ROOT CA 01
           Validity
               Not Before: Feb 12 20:37:43 2023 GMT
               Not After : Feb  7 20:37:43 2043 GMT
           Subject: C = US, ST = Colorado, L = Denver, O = HSM Test, OU = Testing, CN = SPKI SSL ROOT CA 01
           Subject Public Key Info:
               Public Key Algorithm: id-ecPublicKey
                   Public-Key: (384 bit)
                   pub:
                       04:25:24:49:22:da:6c:ae:6d:9b:e9:ac:2f:d1:c0:
                       c3:a4:8a:59:e2:0c:b3:d1:d2:7c:77:cc:37:3c:24:
                       f2:ea:34:8e:76:ac:88:13:20:94:8a:e5:3e:cf:59:
                       4d:b9:3a:9d:49:33:c6:6b:3f:93:af:70:b8:7f:76:
                       be:47:63:56:07:9c:59:75:2b:f9:98:89:56:a1:11:
                       dc:5b:0a:91:e6:29:18:85:73:15:62:4e:d9:43:eb:
                       0a:a2:e0:84:72:3f:8a
                   ASN1 OID: secp384r1
                   NIST CURVE: P-384
           X509v3 extensions:
               X509v3 Subject Key Identifier:
                   15:99:B6:A1:41:50:51:84:2E:A1:55:BD:FB:67:97:E9:32:51:95:75
               X509v3 Authority Key Identifier:
                   keyid:15:99:B6:A1:41:50:51:84:2E:A1:55:BD:FB:67:97:E9:32:51:95:75

               X509v3 Basic Constraints: critical
                   CA:TRUE
       Signature Algorithm: ecdsa-with-SHA512
           30:65:02:31:00:ab:5a:d3:a6:52:e9:78:2f:89:45:48:6c:f1:
           5e:6d:6b:d2:de:a8:03:46:64:5a:9f:34:c0:9c:04:47:1a:b0:
           00:06:11:26:ac:d0:0b:c3:a6:58:66:40:b2:da:88:a3:01:02:
           30:0c:66:00:f8:bb:b7:27:a8:38:ec:07:08:a7:1a:83:b2:01:
           f5:ab:20:ff:e8:a2:1f:bb:4f:ab:3d:2b:53:a3:f1:92:be:a2:
           7b:2d:05:c7:2c:60:74:d7:30:c7:ae:8c:13
   ```

1. Now create the issueing cert, signed by the root CA:

   ```shell
   $ OPENSSL_CONF=hsm.conf /usr/local/opt/openssl@3/bin/openssl req -engine pkcs11 -keyform engine -key REPLACE_WITH_SLOT_NUMBER:02 -new -sha512  -out csr/issue.ca.csr
   Engine "pkcs11" set.
   Enter PKCS#11 token PIN for myca:
   You are about to be asked to enter information that will be incorporated
   into your certificate request.
   What you are about to enter is what is called a Distinguished Name or a DN.
   There are quite a few fields but you can leave some blank
   For some fields there will be a default value,
   If you enter '.', the field will be left blank.
   -----
   Country Name (2 letter code) [AU]:US
   State or Province Name (full name) [Some-State]:Colorado
   Locality Name (eg, city) []:Denver
   Organization Name (eg, company) [Internet Widgits Pty Ltd]:HSM Test
   Organizational Unit Name (eg, section) []:Testing
   Common Name (e.g. server FQDN or YOUR name) []:SPKI SSL ISSUE CA 01
   Email Address []:

   Please enter the following 'extra' attributes
   to be sent with your certificate request
   A challenge password []:
   An optional company name []:
   ```

1. Sign the issuing CA CSR from the root CA.

   ```shell
   $ OPENSSL_CONF=hsm.conf /usr/local/opt/openssl@3/bin/openssl ca -engine pkcs11 -keyform engine -keyfile REPLACE_WITH_SLOT_NUMBER:01 -extensions v3_intermediate_ca -days 3650 -notext -md sha512 -in csr/issue.ca.csr -out certs/issue.ca.cert.pem
   Engine "pkcs11" set.
   Using configuration from hsm.conf
   Enter PKCS#11 token PIN for myca:
   Check that the request matches the signature
   Signature ok
   Certificate Details:
           Serial Number: 4096 (0x1000)
           Validity
               Not Before: Feb 12 20:55:26 2023 GMT
               Not After : Feb  9 20:55:26 2033 GMT
           Subject:
               countryName               = US
               stateOrProvinceName       = Colorado
               organizationName          = HSM Test
               organizationalUnitName    = Testing
               commonName                = SPKI SSL ISSUE CA 01
           X509v3 extensions:
               X509v3 Subject Key Identifier:
                   99:1F:C7:6A:8B:32:B5:F0:E0:69:53:53:2A:2E:E2:D9:E2:F1:D4:0E
               X509v3 Authority Key Identifier:
                   15:99:B6:A1:41:50:51:84:2E:A1:55:BD:FB:67:97:E9:32:51:95:75
               X509v3 Basic Constraints: critical
                   CA:TRUE, pathlen:0
               X509v3 Key Usage: critical
                   Digital Signature, Certificate Sign, CRL Sign
   Certificate is to be certified until Feb  9 20:55:26 2033 GMT (3650 days)
   Sign the certificate? [y/n]:y


   1 out of 1 certificate requests certified, commit? [y/n]y
   Write out database with 1 new entries
   Data Base Updated
   ```

1. Verify issue CA certificate:

   ```shell
   $ openssl x509 -in certs/issue.ca.cert.pem -noout -text
   Certificate:
       Data:
           Version: 3 (0x2)
           Serial Number: 4096 (0x1000)
           Signature Algorithm: ecdsa-with-SHA512
           Issuer: C = US, ST = Colorado, L = Denver, O = HSM Test, OU = Testing, CN = SPKI SSL ROOT CA 01
           Validity
               Not Before: Feb 12 20:55:26 2023 GMT
               Not After : Feb  9 20:55:26 2033 GMT
           Subject: C = US, ST = Colorado, O = HSM Test, OU = Testing, CN = SPKI SSL ISSUE CA 01
           Subject Public Key Info:
               Public Key Algorithm: id-ecPublicKey
                   Public-Key: (384 bit)
                   pub:
                       04:17:6a:04:7e:28:dd:e4:7c:0c:62:9a:33:f8:13:
                       68:02:09:ba:21:ba:1f:c7:c2:f0:3a:03:81:4a:65:
                       90:a8:39:71:df:e1:77:a3:a6:c3:51:32:f4:5a:7b:
                       a9:ba:27:c7:44:87:16:26:ed:f2:22:70:b2:24:c7:
                       51:4c:09:ec:7d:af:9c:3e:22:3e:3f:41:73:83:7e:
                       2c:31:c6:6d:e0:48:ba:10:74:7f:98:7a:74:42:ff:
                       6b:e9:ad:1e:72:f8:51
                   ASN1 OID: secp384r1
                   NIST CURVE: P-384
           X509v3 extensions:
               X509v3 Subject Key Identifier:
                   99:1F:C7:6A:8B:32:B5:F0:E0:69:53:53:2A:2E:E2:D9:E2:F1:D4:0E
               X509v3 Authority Key Identifier:
                   keyid:15:99:B6:A1:41:50:51:84:2E:A1:55:BD:FB:67:97:E9:32:51:95:75

               X509v3 Basic Constraints: critical
                   CA:TRUE, pathlen:0
               X509v3 Key Usage: critical
                   Digital Signature, Certificate Sign, CRL Sign
       Signature Algorithm: ecdsa-with-SHA512
           30:65:02:31:00:f6:53:0a:9a:23:f5:1d:c0:69:61:e4:5e:8a:
           3e:b5:b4:2a:8e:32:5b:6e:0f:21:10:0e:68:1f:a1:04:6f:f3:
           db:1f:39:61:ac:c2:e8:6e:d0:5e:1c:26:54:25:07:67:0f:02:
           30:70:2a:3a:12:49:ec:7a:75:20:05:4a:b4:b3:73:f1:5d:5d:
           52:d1:97:66:27:79:4e:3a:7f:0c:5c:2c:d9:79:99:48:9c:4c:
           b6:bd:dc:ec:94:3c:25:b8:72:45:ed:f7:0c
   ```

1. Combine certifcate chain & verify.

   ```shell
   $ cat certs/issue.ca.cert.pem certs/root.ca.cert.pem > certs/spki.cert.pem
   $ openssl x509 -in certs/spki.cert.pem  -noout -text
   (No errors returned from openssl)
   ```

#### Create and self-signed a client certificate from issuing CA

This is just demonstrating a client certificate in the same slot as the CAs, but with a different Id and name. For this example, Id of `03` will be used.

1. Create a new slot as the AWS SDKs cannot reference by Id. Use the new undefined slot number (e.g., `1`).

   ```shell
   $ softhsm2-util --init-token --slot 1 --label myclient
   === SO PIN (4-255 characters) ===
   Please enter SO PIN: ****
   Please reenter SO PIN: ****
   === User PIN (4-255 characters) ===
   Please enter user PIN: ****
   Please reenter user PIN: ****
   The token has been initialized and is reassigned to slot 1234567890
   ```

1. Create the key pair (USER PIN of `1234` used), and for the heck of it, show the slot contents of all three keys.

   ```shell
   $ pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -l --keypairgen --key-type EC:secp384r1 --slot REPLACE_WITH_CLIENT_SLOT_NUMBER --id 01 --label "hsm_thing1"
   $ pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -l -O --slot REPLACE_WITH_CLIENT_SLOT_NUMBER
   Logging in to "myclient".
   Please enter User PIN:
   Public Key Object; EC  EC_POINT 384 bits
   EC_POINT:  0461040b3890fa20792ab32e41936e6b3394131e3780b9f7287927d53a6985ee06477e78afb8335a908d718e7d0db2b604113f701af6c61c8bad36257a9f581c904186e6092b24bdab7e746080ae3062f59d2d5f348f80b9675fa3ae875828ed0242c
   EC_PARAMS:  06052b81040022
   label:      hsm_thing1
   ID:         01
   Usage:      encrypt, verify, wrap, derive
   Access:     local
   Private Key Object; EC
   label:      hsm_thing1
   ID:         01
   Usage:      decrypt, sign, unwrap, derive
   Access:     sensitive, always sensitive, never extractable, local
   ```

1. Generate the CSR

   ```shell
   $ OPENSSL_CONF=hsm.conf /usr/local/opt/openssl@3/bin/openssl req -engine pkcs11 -keyform engine -key REPLACE_WITH_CLIENTSLOT_NUMBER:01 -new -sha512  -out csr/hsm_thing1.client.csr
   Engine "pkcs11" set.
   Enter PKCS#11 token PIN for myca:
   You are about to be asked to enter information that will be incorporated
   into your certificate request.
   What you are about to enter is what is called a Distinguished Name or a DN.
   There are quite a few fields but you can leave some blank
   For some fields there will be a default value,
   If you enter '.', the field will be left blank.
   -----
   Country Name (2 letter code) [AU]:US
   State or Province Name (full name) [Some-State]:Colorado
   Locality Name (eg, city) []:Denver
   Organization Name (eg, company) [Internet Widgits Pty Ltd]:AWS IoT HSM Testing
   Organizational Unit Name (eg, section) []:Testing
   Common Name (e.g. server FQDN or YOUR name) []:hsm_thing1
   Email Address []:

   Please enter the following 'extra' attributes
   to be sent with your certificate request
   A challenge password []:
   An optional company name []:
   ```

1. Sign the certifcate from the issuing CA. The `-extensions user_crt -extfile hsm.conf` is added t the command to ensur the X509v3 extensions are included in the signed certificate.

```shell
$ OPENSSL_CONF=hsm.conf /usr/local/opt/openssl@3/bin/openssl x509 -req -engine pkcs11 \
-in csr/hsm_thing.client.csr -CAkeyform engine -CAkey REPLACE_WITH_SLOT_NUMBER:02 \
-CA certs/spki.cert.pem -CAcreateserial -extensions usr_cert -extfile hsm.conf \
-days 365 -sha256 -out certs/hsm_thing.client.cert.pem
Engine "pkcs11" set.
Certificate request self-signature ok
subject=C = US, ST = Colorado, L = Denver, O = AWS IoT HSM Testing, OU = Testing, CN = hsm_thing
Enter PKCS#11 token PIN for myca:
```

1. Convert the certificate and import the client certificate into the same slot and with the same Id (03).

   ```shell
   $ openssl x509 -outform DER -in certs/hsm_thing1.client.cert.pem -out /tmp/hsm_thing1.client.cert.der
   $ pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -l --write-object \
   /tmp/hsm_thing1.client.cert.der --type cert --id 01 --slot REPLACE_WITH_CLIENT_SLOT_NUMBER
   Logging in to "myclient".
   Please enter User PIN:
   Created certificate:
   Certificate Object; type = X.509 cert
   label:
   subject:    DN: C=US, ST=Colorado, L=Denver, O=AWS IoT HSM Testing, OU=Testing, CN=hsm_thing
   serial:     3639047C8B90E708F642FE8F930854F529D6D0BA
   ID:         03
   ```

   The certificate can be exported from the HSM if needed. The AWS IoT Core Credential Provider Helper requires the certificate to be in PEM format and located on disk (`cert_file_path`) or in _bytes_ format (`cert_file_contents`).

1. Register the certificate with AWS IoT Core using the CLI. Ironically we'll use local ~/.aws/crdentials for this operation instead of doing it via boto3. 😄

   ```shell
   $ aws --region us-west-2 iot register-certificate-without-ca --certificate-pem file://certs/hsm_thing1.client.cert.pem --status ACTIVE
   {
       "certificateArn": "arn:aws:iot:us-west-2:1234567890:cert/4f10c042fc96a401ee3c45095XXXXXXXXXX22f273191b1591b763c77654cd401",
       "certificateId": "4f10c042fc96a401ee3c45095XXXXXXXXXX2f273191b1591b763c77654cd401"
   }
   ```

Attach the AWS IoT certificate to a thing and policy allowing credential provider access. At this point, the certificate file and providing the PKCS#11 material should be available for use. See the advanced usage section for creating a session object from PKCS#11 credentials.

## Ubuntu in Docker for testing

This will run a docker image, create the HSM, and self-sign a certificate and private key for testing.

See the [dockerfile](../../docker/hsm_linux/hsm_linux.dockerfile) for installation of dependencies.

1. Initialize slot

   ```shell
   $ export SLOT=$(softhsm2-util --init-token --free  --so-pin 1234 --pin 1234 --label hsm_thing|pcregrep -o1 '.* to slot (.*)')
   ```

1. Generate private key and self-signed certificate

   ```shell
   $ openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
       -keyout hsm_thing.key -out hsm_thing-cert.pem -sha256 -days 365 -nodes \
       -subj 'C=US' -subj '/CN=hsm_thing/C=US/ST=Colorado/L=Denver/O=Testing-R-Us/OU=PKCS Crew' \
       -addext subjectKeyIdentifier=hash \
       -addext authorityKeyIdentifier='keyid,issuer' \
       -addext keyUsage='critical,digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment' \
       -addext basicConstraints='critical,CA:FALSE'
   ```

1. Import the key into the HSM

   ```shell
   $ softhsm2-util --import hsm_thing.key --slot $(cat slot.txt) --label hsm_thing_key --id 0000 --pin 1234
   ```

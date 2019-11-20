# Go TLS Example

An example of using self-signed TLS keys and certificates with Go clients and servers. This shows
how to use client certificates to authenticate TCP and HTTP connections. We generate the
certificates using the openssl command-line tool, then reads them using Go clients and servers.

## Programs

* `echoclient`: TLS echo server: reads from stdin, writes to the server, reads from server, then prints on stdout.
* `echoserver`: TLS echo server: echos data to/from TLS connections.
* `endtoend`: Runs the echoclient and echoserver in various combinations to ensure they work.


## Generating keys

For more secure and robust configuration, see https://jamielinux.com/docs/openssl-certificate-authority/introduction.html

### Generate the certificate authority key

Some documentation suggests using a root key and an intermediate key, but this is only going
to use a root key. We need the "extension" fields to indicate that this is a CA root key. Create
a config file `ca_config.cnf` with the following contents (see man x509v3_config):

```
[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]
# empty; see
# https://superuser.com/questions/947061/openssl-unable-to-find-distinguished-name-in-config/1118045

[v3_ca_config]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
```

Generate the key and certificate:
```
openssl ecparam -genkey -out cakey.pem -name prime256v1
openssl req -new -x509 -sha256 -key cakey.pem -out cacert.pem -config ca_config.cnf -extensions v3_ca_config -days 3650 -subj "/O=Example Inc/CN=Example Inc Root CA" 
```

You can inspect the certificate with `openssl x509 -text -in cacert.pem -noout`:

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 15122786380862923150 (0xd1deee16e573218e)
    Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=Example Inc, CN=Example Inc Root CA
        Validity
            Not Before: Nov 20 18:48:52 2019 GMT
            Not After : Nov 17 18:48:52 2029 GMT
        Subject: O=Example Inc, CN=Example Inc Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    ...
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                B9:50:94:1F:12:4C:7C:0E:8B:42:D9:ED:6D:23:D9:A8:AA:CE:76:8A
            X509v3 Authority Key Identifier: 
                keyid:B9:50:94:1F:12:4C:7C:0E:8B:42:D9:ED:6D:23:D9:A8:AA:CE:76:8A

            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
    Signature Algorithm: ecdsa-with-SHA256
         ...
```

### Generate the server key and certificate for `localhost`

The process is:

1. Create a public/private key pair.
2. Use the private key to create a certificate signing request (CSR) this will embed a name (CN).
3. Use the certificate authorite (CA) key to take the CSR and produce the signed certificate.

```
openssl ecparam -genkey -out serverkey.pem -name prime256v1
openssl req -new -sha256 -key serverkey.pem -out serverkey.csr -days 1095 -subj "/O=Example Inc/CN=localhost"
openssl x509 -req -in serverkey.csr -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out servercert.pem -days 1095
```

Inspecting the generated certificate with `openssl x509 -text -in servercert.pem -noout`:

```
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number: 15839831314861158550 (0xdbd262a868687096)
    Signature Algorithm: ecdsa-with-SHA1
        Issuer: O=Example Inc, CN=Example Inc Root CA
        Validity
            Not Before: Nov 20 18:52:33 2019 GMT
            Not After : Nov 19 18:52:33 2022 GMT
        Subject: O=Example Inc, CN=localhost
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub: 
                    ...
                ASN1 OID: prime256v1
                NIST CURVE: P-256
    Signature Algorithm: ecdsa-with-SHA1
         ...
```

### Generate the client key and certificate

Follow the same process above. In this case, the CN (common name) is less important or clear.
Unless I find better recommendations, it seems useful to put something human understandable in
this, to help identify the client.


### Certificate recommendations

See https://wiki.mozilla.org/Security/Server_Side_TLS

Certificates: Modern = ECDSA P-256; Intermediate = RSA 2048-bits

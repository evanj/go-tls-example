# Go TLS Example

An example of using self-signed TLS keys and certificates with Go clients and servers. This shows
how to use client certificates to authenticate TCP and HTTP connections. We generate the
certificates using the openssl command-line tool, then reads them using Go clients and servers.

##

* `echoclient`: A TLS echo server: reads from stdin, writes to the server, reads from server, then prints on stdout.
* `echoserver`: A TLS echo server: requires authenticated connections, then echos data.


## Generating keys

### Generate the certificate authority key

We can use the same key as both the server key and the authority key.



### Certificate recommendations

See https://wiki.mozilla.org/Security/Server_Side_TLS

Certificates: Modern = ECDSA P-256; Intermediate = RSA 2048-bits


https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html


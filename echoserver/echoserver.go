package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net"
)

// Key/cert recommendations from https://wiki.mozilla.org/Security/Server_Side_TLS
// How to do this "properly" see:
// https://jamielinux.com/docs/openssl-certificate-authority/appendix/root-configuration-file.html

// NOTE: We can use a single server and authority key! It might be better to use separate.

// Create the server/CA key
// openssl ecparam -genkey -out cakey.pem -name prime256v1
// openssl req -new -x509 -sha256 -key cakey.pem -out cacert.pem -days 1095 -subj "/O=Bluecore Inc/CN=localhost"

// Create the client key and certificate, signed by the CA key

// To use a separate CA and server:

// Create the CA key and cert
// openssl ecparam -genkey -out cakey.pem -name prime256v1
// openssl req -new -x509 -sha256 -key cakey.pem -out cacert.pem -days 1095 -subj "/O=Bluecore Inc"
// NOTE: This won't have CA:TRUE or key usage bits; -extensions v3_ca might help

// Create the server key and cert
// openssl ecparam -genkey -out serverkey.pem -name prime256v1
// openssl req -new -sha256 -key serverkey.pem -out serverkey.csr -days 1095 -subj "/O=Bluecore Inc/CN=localhost"
// openssl x509 -req -in serverkey.csr -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out servercert.pem -days 1095
// check it with: openssl x509 -text -in cert.pem -noout

const key = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIOY36v3ybwSq3/bd8XdFVf8aYaNWAGYZZXKSBU+qmTqXoAoGCCqGSM49
AwEHoUQDQgAEgKXyK9/QMEnpejKnf3qWGkkR3rv67UxsnfWiW6vYp7Mh9xs968eN
hB1/5C7SfbLQGyY84vAm1jb10YZWZD+Hsg==
-----END EC PRIVATE KEY-----`

const certificateWithCN = `-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIJAImDoLNBzG5pMAoGCCqGSM49BAMCMCsxFTATBgNVBAoM
DEJsdWVjb3JlIEluYzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE2MTIxNjIxMDUw
NFoXDTE5MTIxNjIxMDUwNFowKzEVMBMGA1UECgwMQmx1ZWNvcmUgSW5jMRIwEAYD
VQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASApfIr39Aw
Sel6Mqd/epYaSRHeu/rtTGyd9aJbq9insyH3Gz3rx42EHX/kLtJ9stAbJjzi8CbW
NvXRhlZkP4eyo1AwTjAdBgNVHQ4EFgQU8HojMJXOYvIpbPyCeuWUvNSA/SwwHwYD
VR0jBBgwFoAU8HojMJXOYvIpbPyCeuWUvNSA/SwwDAYDVR0TBAUwAwEB/zAKBggq
hkjOPQQDAgNIADBFAiB3wawLITpnnq/PPj2boVcrn9V/23P3AMHMKb7FH/E/ogIh
APCY7jmCeJ1sbnrvAth0KeYl9niP47DMMilqZt3Qt6HO
-----END CERTIFICATE-----`

// RSA for older clients (e.g. OpenSSL with Mac OS X 10.11)
// openssl genrsa -out serverkey_rsa.pem 2048
// openssl req -new -x509 -sha256 -key serverkey_rsa.pem -out serverkey_rsa_cert.pem -days 1095 -subj "/O=Bluecore Inc/CN=localhost"
const rsaKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwe9/DhNezYq9fUVH4k9H8K+bjoaRoAKI3pd9Jle2G1bSF7FV
w9UOUPTGyN0NNxkTo7n0aKG4muxiTMf+J4Vev7M+39qkWO05J/SaqRsf/jmpZrbx
okf5ZYy70RB3K40e5wnuIiRpYulORD4CKbR2D7cqnh+kS2jklz6pzG+cg/1/36Rf
eZzTJBClRaA3kZfazfSIILcBwcxkkJneyz7yY3Ims0uoaiIUBggfLaplkw2tGgUC
XqYGnpX8ZwP5tLlSs94+T6xb6/odFJSxpR6JL8U/OP6wM+ZmQq3wT+ccSdmaj19+
zsfW6TsTc9mnMb91hWZxYX6tz3Vo/bdQ5R/Y4QIDAQABAoIBAG5oKE8dG/WsLKBq
lrfyJqSRdN+5IKKVjtIaMDdp69S4ora2UHtCifnwwFKN9f4OGq41KT2ABBa+yF+p
47kgJobARuUuFi5CLy3eBUaMmLQko5pEQGAA1azIaAxncVCr8JHbh2SMkiqrY9FZ
8+VGRYhA4NRQczozJyArnoMyb0p8Q1JvsJOyMWyM5jyBr8d4sYDoilI1kMBMnVLw
QSxJxRT4LEamNK74HZiC87kQ6FKeN0pknKuma9F4zNi1k1LOHLkDoV0tdf9xs+dp
NGmsCaIyZKB47G/EVvlpj4Sd0XiQCLmj1eijCJv/koV1oNCkE8hztwJFpzHIPVXp
g9NnWKECgYEA49ed9VukVn0vNKUoSfO5OW7Gw1AmQ8JUflqzH8Jq/WmrPzt9eP/J
Wp6k+uGcWZ1pKE+tBN0NMWxl/ZOlnOFlnALRzmnFWCfgOlMqubSyTBLTbhV9xK0X
FpXkG9M21kg6qL6yv7KmkPmwqJmJ7RuWjw+wISBSq2fVZfPrqwQZcw0CgYEA2ecm
4DhhwtNTpmIjxxMu44FHoMJ1he1fS/f5FEb1Z2RQCrroKsvlnOyzfM82srIRTOui
09P+zBy8AfGxd9DVVE3+mhObi2yNIoSdMnmQ5bJi6kXla4daeD3O1R36WU/RMFo6
mlRRkbFK5ATBVismTb+H6A6Vu+aNOzf3k58NGCUCgYEAsfiish07aTOvw/eeWOXA
MVSOfdIFkbgiN/CxKoW6/OellGbrw7BJoDd7t1yzvGxwz8Qs6jehLpH1uPWzz69g
p1Ssfgew1wOO6wA7x4OWIkYyUTMIYrCx8Dp1TCbYFtmkuFr9VTA/W88uZwRH8KY0
HNusQLP231zkHBdEZvl0x6ECgYEAk4FSY75HD2eW3K7aoUxvFTrSjhSVEdAaDocS
aZOPVContNvJhg74pD3nUrnCwTyhUXzBgLulY+6fpoFCLWWEw8j4bLyRMtSMxa0X
7K82UwdqxkQChcPejj7o4IOmkQbjCORLf2VMwl9N3wUJC5eyGjdpfMFCwyvStx+v
zJKCfrECgYBqli0WRMLB8/pblrZLYH3fFeYbh7w0jiu5kpeqiPHfRtLrXGLz3q4Q
W+udwvNEezccl6vPWnjgXhjMOz9BkbbQXu25IdZZCoitAuoYaUL6BPeg2JSBqIDH
phXsf/9zVEjfvVW1VHVXHY8DI0ytdBsk8YPmUpFmRezPWzeTCtYchw==
-----END RSA PRIVATE KEY-----`

const rsaCert = `-----BEGIN CERTIFICATE-----
MIIDZzCCAk+gAwIBAgIJANG/mbEbHoJrMA0GCSqGSIb3DQEBCwUAMCsxFTATBgNV
BAoTDEJsdWVjb3JlIEluYzESMBAGA1UEAxMJbG9jYWxob3N0MB4XDTE2MTIxNzE4
MzAxMFoXDTE5MTIxNzE4MzAxMFowKzEVMBMGA1UEChMMQmx1ZWNvcmUgSW5jMRIw
EAYDVQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQDB738OE17Nir19RUfiT0fwr5uOhpGgAojel30mV7YbVtIXsVXD1Q5Q9MbI3Q03
GROjufRoobia7GJMx/4nhV6/sz7f2qRY7Tkn9JqpGx/+OalmtvGiR/lljLvREHcr
jR7nCe4iJGli6U5EPgIptHYPtyqeH6RLaOSXPqnMb5yD/X/fpF95nNMkEKVFoDeR
l9rN9IggtwHBzGSQmd7LPvJjciazS6hqIhQGCB8tqmWTDa0aBQJepgaelfxnA/m0
uVKz3j5PrFvr+h0UlLGlHokvxT84/rAz5mZCrfBP5xxJ2ZqPX37Ox9bpOxNz2acx
v3WFZnFhfq3PdWj9t1DlH9jhAgMBAAGjgY0wgYowHQYDVR0OBBYEFDmlNJnIGO2u
kOBSKIabT/Aqi+fTMFsGA1UdIwRUMFKAFDmlNJnIGO2ukOBSKIabT/Aqi+fToS+k
LTArMRUwEwYDVQQKEwxCbHVlY29yZSBJbmMxEjAQBgNVBAMTCWxvY2FsaG9zdIIJ
ANG/mbEbHoJrMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGlfnhSn
UXT2MNj3rT5wVi4fkBf9HmQCjwU0wxgXz9n5ussNr1Anj5L52fh9sxXz5hnpeyaz
yXnrT7F3W0lP8CxombX8ORbENsgQGab4OGi3YsSn2ZZNsVVgM4QnNwwkqqL42QSw
UzhnpUalgtckomALDyRgjLVtevN+E+Z4eu2v71lKrPUKOo1W7dTRmuxzV7z5Qabm
TrxgH3gZHeBKs/MY2FB95V4A//hRYWeH0H1xUUKOEiH6tkN8UumEmr+cNBs7QFbD
ZypgfhagyCdw+cyTlQRlvVnjQZo8ClL8Q25/xGvvJOFBlyY6U5EfJCzeYgXkNUcp
3Cxn3O56lPYWonk=
-----END CERTIFICATE-----`

func listenTLS(addr string, authType tls.ClientAuthType, certPool *x509.CertPool) (net.Listener, error) {
	cert, err := tls.X509KeyPair([]byte(rsaCert), []byte(rsaKey))
	// cert, err := tls.X509KeyPair([]byte(certificateWithCN), []byte(key))
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   authType,
		ClientCAs:    certPool,
	}
	return tls.Listen("tcp", addr, config)
}

func listenNoTLS(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}

// Returns a unique binary representation for pub. This can be used to identify specific clients.
func marshalPublicKey(pub interface{}) ([]byte, error) {
	var publicKeyBytes []byte
	var err error
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		// Stolen from https://golang.org/src/crypto/x509/x509.go?s=2771:2829#L87
		publicKeyBytes = elliptic.Marshal(p.Curve, p.X, p.Y)
	case *rsa.PublicKey:
		// TODO: Append exponent
		publicKeyBytes = p.N.Bytes()
	default:
		return nil, fmt.Errorf("Unsupported public key type: %T", pub)
	}
	return publicKeyBytes, err
}

func handleConn(conn net.Conn) {
	clientAddrString := conn.RemoteAddr().String()
	fmt.Printf("echoserver connection from %s\n", clientAddrString)
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		fmt.Printf("echoserver read from %s: %s; echoing ...\n", clientAddrString, scanner.Text())

		lineWithNewLine := append(scanner.Bytes(), '\n')
		_, err := conn.Write(lineWithNewLine)
		if err != nil {
			panic(err)
		}
	}
	if scanner.Err() != nil {
		panic(scanner.Err())
	}

	fmt.Printf("echoserver connection from %s closed\n", clientAddrString)
}

func main() {
	addr := flag.String("addr", ":7000", "listen address")
	useTLS := flag.Bool("useTLS", true, "require TLS connections")
	// msglen := flag.Int("msglen", 0, "If > 0, read a fixed size message (needed for TLS: no CloseWrite)")
	// requestClientCert := flag.Bool("requestClientCert", false, "Request client certificate")
	// requireClientCert := flag.Bool("requireClientCert", false, "Require client certificate")
	// verifyClientCert := flag.Bool("verifyClientCert", false, "Require client certificate (use -trustSelf)")
	// trustSelf := flag.Bool("trustSelf", false, "Trust client certificates signed by us. "+
	// 	"Correct clients (e.g. Go) only send matching certificates, so this may cause no certificate errors.")
	flag.Parse()

	if *useTLS {
		panic("todo")
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go handleConn(conn)
	}

	// authType := tls.NoClientCert
	// if *requestClientCert {
	// 	fmt.Println("requesting client certificates")
	// 	authType = tls.RequestClientCert
	// } else if *requireClientCert {
	// 	fmt.Println("requiring any client certificate")
	// 	authType = tls.RequireAnyClientCert
	// } else if *verifyClientCert {
	// 	fmt.Println("requiring a verified client certificate")
	// 	authType = tls.RequireAndVerifyClientCert
	// }

	// var certPool *x509.CertPool
	// if *trustSelf {
	// 	certPool = x509.NewCertPool()
	// 	ok := certPool.AppendCertsFromPEM([]byte(rsaCert))
	// 	// ok := certPool.AppendCertsFromPEM([]byte(certificateWithCN))
	// 	if !ok {
	// 		panic(errors.New("no valid certificates parsed"))
	// 	}
	// 	fmt.Println("Trusting own key/certificate to validate client certificates")
	// }

	// listener, err := listenTLS(*addr, authType, certPool)
	// if err != nil {
	// 	panic(err)
	// }
	// for {
	// 	c, err := listener.Accept()
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fmt.Println("connection from", c.RemoteAddr().String())

	// 	if tlsConn, ok := c.(*tls.Conn); ok {
	// 		if !tlsConn.ConnectionState().HandshakeComplete {
	// 			fmt.Println("completing handshake ...")
	// 			err = tlsConn.Handshake()
	// 			if err != nil {
	// 				fmt.Println("ERROR:", err.Error())
	// 				tlsConn.Close()
	// 				continue
	// 			}
	// 		}
	// 		state := tlsConn.ConnectionState()
	// 		fmt.Println("TLS connection:")
	// 		fmt.Println("  DidResume:", state.DidResume)
	// 		fmt.Printf("  CipherSuite: 0x%04x\n", state.CipherSuite)
	// 		fmt.Printf("  Version: 0x%04x\n", state.Version)
	// 		if len(state.PeerCertificates) > 0 {
	// 			fmt.Println("  Peer certificates:", len(state.PeerCertificates))
	// 			fmt.Println("  Peer 1 Issuer:", state.PeerCertificates[0].Issuer.ToRDNSequence())
	// 			fmt.Println("  Peer 1 Subject:", state.PeerCertificates[0].Subject.ToRDNSequence())
	// 			fmt.Println("  Peer 1 Serial Number:", hex.EncodeToString(state.PeerCertificates[0].SerialNumber.Bytes()))
	// 			fmt.Println("  Peer 1 Subject Key ID:", hex.EncodeToString(state.PeerCertificates[0].SubjectKeyId))
	// 			fmt.Println("  Peer 1 Authority ID:", hex.EncodeToString(state.PeerCertificates[0].AuthorityKeyId))
	// 			// matches the output shown in browsers and openssl -text
	// 			pubKey, err := marshalPublicKey(state.PeerCertificates[0].PublicKey)
	// 			if err != nil {
	// 				panic(err)
	// 			}
	// 			fmt.Println("  Peer 1 Public Key:", hex.EncodeToString(pubKey))
	// 		}
	// 	}

	// 	var input []byte
	// 	if *msglen > 0 {
	// 		input = make([]byte, *msglen)
	// 		_, err = io.ReadFull(c, input)
	// 	} else {
	// 		input, err = ioutil.ReadAll(c)
	// 	}
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fmt.Printf("Read %d bytes; echoing\n", len(input))

	// 	_, err = c.Write(input)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fmt.Println("Wrote; closing socket")
	// 	err = c.Close()
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }
}

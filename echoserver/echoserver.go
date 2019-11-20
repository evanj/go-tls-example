package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
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
	defer conn.Close()

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
		fmt.Printf("echoserver ERROR from %s closing connection: %s\n", clientAddrString, scanner.Err().Error())
		return
	}

	err := conn.Close()
	if err != nil {
		panic(err)
	}
	fmt.Printf("echoserver connection from %s closed\n", clientAddrString)
}

func listenTLS(addr string, serverCertPath string, serverKeyPath string) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	return tls.Listen("tcp", addr, cfg)
}

func main() {
	addr := flag.String("addr", ":7000", "listen address")
	certPath := flag.String("cert", "", "path to the server cert")
	keyPath := flag.String("key", "", "path to the server key")
	// msglen := flag.Int("msglen", 0, "If > 0, read a fixed size message (needed for TLS: no CloseWrite)")
	// requestClientCert := flag.Bool("requestClientCert", false, "Request client certificate")
	// requireClientCert := flag.Bool("requireClientCert", false, "Require client certificate")
	// verifyClientCert := flag.Bool("verifyClientCert", false, "Require client certificate (use -trustSelf)")
	// trustSelf := flag.Bool("trustSelf", false, "Trust client certificates signed by us. "+
	// 	"Correct clients (e.g. Go) only send matching certificates, so this may cause no certificate errors.")
	flag.Parse()

	var listener net.Listener
	var err error
	if *certPath != "" && *keyPath != "" {
		fmt.Printf("echoserver listening for TLS with addr=%s cert=%s key=%s\n",
			*addr, *certPath, *keyPath)
		listener, err = listenTLS(*addr, *certPath, *keyPath)
	} else {
		fmt.Printf("echoserver listening without TLS with addr=%s\n", *addr)
		listener, err = net.Listen("tcp", *addr)
	}
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

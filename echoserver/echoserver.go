package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
)

// from https://golang.org/src/crypto/tls/cipher_suites.go
var cipherSuiteNames = map[uint16]string{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	tls.TLS_AES_128_GCM_SHA256:                  "TLS_AES_128_GCM_SHA256",
}

// from https://golang.org/src/crypto/tls/common.go
var versionNames = map[uint16]string{
	tls.VersionTLS12: "TLS12",
	tls.VersionTLS13: "TLS13",
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

// Echos lines from conn and closes it.
func handleConn(logger serverLogger, conn net.Conn) error {
	defer conn.Close()

	if tlsConn, ok := conn.(*tls.Conn); ok {
		if !tlsConn.ConnectionState().HandshakeComplete {
			logger.logf("completing TLS handshake ...")
			err := tlsConn.Handshake()
			if err != nil {
				return err
			}
		}
		state := tlsConn.ConnectionState()
		logger.logf("  DidResume: %t", state.DidResume)
		logger.logf("  CipherSuite: 0x%04x (%s)", state.CipherSuite, cipherSuiteNames[state.CipherSuite])
		logger.logf("  Version: 0x%04x (%s)", state.Version, versionNames[state.Version])
		if len(state.PeerCertificates) > 0 {
			logger.logf("  Peer certificates: %d", len(state.PeerCertificates))
			logger.logf("  Peer 1 Issuer: %s", state.PeerCertificates[0].Issuer.ToRDNSequence())
			logger.logf("  Peer 1 Subject: %s", state.PeerCertificates[0].Subject.ToRDNSequence())
			logger.logf("  Peer 1 Serial Number: %s", hex.EncodeToString(state.PeerCertificates[0].SerialNumber.Bytes()))
			logger.logf("  Peer 1 Subject Key ID: %s", hex.EncodeToString(state.PeerCertificates[0].SubjectKeyId))
			logger.logf("  Peer 1 Authority ID: %s", hex.EncodeToString(state.PeerCertificates[0].AuthorityKeyId))
			// matches the output shown in browsers and openssl -text
			pubKey, err := marshalPublicKey(state.PeerCertificates[0].PublicKey)
			if err != nil {
				return err
			}
			logger.logf("  Peer 1 Public Key: %s", hex.EncodeToString(pubKey))
		}
	}

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		logger.logf("read %#v; echoing ...", scanner.Text())

		lineWithNewLine := append(scanner.Bytes(), '\n')
		_, err := conn.Write(lineWithNewLine)
		if err != nil {
			return err
		}
	}
	if scanner.Err() != nil {
		return scanner.Err()
	}

	return conn.Close()
}

type serverLogger interface {
	logf(message string, args ...interface{})
}

type clientLogger struct {
	clientAddrString string
}

func (c *clientLogger) logf(message string, args ...interface{}) {
	args = append([]interface{}{c.clientAddrString}, args...)
	fmt.Printf("echoserver %s: "+message+"\n", args...)
}

func handleConnGoroutine(conn net.Conn) {
	logger := &clientLogger{conn.RemoteAddr().String()}
	logger.logf("connection started")
	err := handleConn(logger, conn)
	if err != nil {
		logger.logf("ERROR %s (connection closed)", err.Error())
	} else {
		logger.logf("connection closed (no error)")
	}
}

func listenTLS(
	addr string, serverCertPath string, serverKeyPath string, clientCARootCertPath string,
) (net.Listener, error) {
	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, err
	}

	var certPool *x509.CertPool
	clientAuth := tls.NoClientCert
	if clientCARootCertPath != "" {
		certBytes, err := ioutil.ReadFile(clientCARootCertPath)
		if err != nil {
			return nil, err
		}

		certPool = x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(certBytes)
		if !ok {
			return nil, errors.New("caCert did not contain any certificates")
		}
		clientAuth = tls.RequireAndVerifyClientCert
		fmt.Printf("echoserver: requiring cert=%s for verifying client certificates\n", clientCARootCertPath)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    certPool,
		ClientAuth:   clientAuth,
	}
	return tls.Listen("tcp", addr, cfg)
}

func main() {
	addr := flag.String("addr", "localhost:7000", "listen address")
	certPath := flag.String("cert", "", "path to the server cert")
	keyPath := flag.String("key", "", "path to the server key")
	clientCARootCertPath := flag.String("clientCARootCert", "",
		"Path to the root CA certificate to verify client certs")
	flag.Parse()

	var listener net.Listener
	var err error
	if *certPath != "" {
		fmt.Printf("echoserver listening for TLS with addr=%s cert=%s key=%s\n",
			*addr, *certPath, *keyPath)
		listener, err = listenTLS(*addr, *certPath, *keyPath, *clientCARootCertPath)
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
		go handleConnGoroutine(conn)
	}
}

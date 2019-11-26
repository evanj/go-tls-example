package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/evanj/go-tls-example/cmdline"
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

func main() {
	config, err := cmdline.ParseServer(cmdline.PrefixLogf("echoserver: "))
	if err != nil {
		panic(err)
	}

	var listener net.Listener
	if config.TLSConfig != nil {
		fmt.Printf("echoserver listening for TLS with addr=%s\n", config.Addr)
		listener, err = tls.Listen("tcp", config.Addr, config.TLSConfig)
	} else {
		fmt.Printf("echoserver listening without TLS with addr=%s\n", config.Addr)
		listener, err = net.Listen("tcp", config.Addr)
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

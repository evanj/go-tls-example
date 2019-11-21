package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
)

func main() {
	addr := flag.String("addr", "localhost:7000", "echo server address")
	useTLS := flag.Bool("useTLS", true, "Use TLS. If false, uses an unencrypted TCP connection")
	useSessionCache := flag.Bool("useSessionCache", false,
		"Enable session cache and make a second request to test session resumption")
	insecureSkipVerify := flag.Bool("insecureSkipVerify", false, "skips verifying the server's certificate")
	clientCertPath := flag.String("cert", "", "path to a client certificate to use")
	clientKeyPath := flag.String("key", "", "path to a client key to use")
	trustedRootPath := flag.String("trustedRoot", "", "path to a trusted root certificate")
	flag.Parse()

	certificates := []tls.Certificate{}
	if *clientCertPath != "" {
		cert, err := tls.LoadX509KeyPair(*clientCertPath, *clientKeyPath)
		if err != nil {
			panic(err)
		}
		certificates = []tls.Certificate{cert}
		fmt.Printf("echoclient: using client cert=%s key=%s\n", *clientCertPath, *clientKeyPath)
	}

	var certPool *x509.CertPool
	if *trustedRootPath != "" {
		certBytes, err := ioutil.ReadFile(*trustedRootPath)
		if err != nil {
			panic(err)
		}

		certPool = x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(certBytes)
		if !ok {
			panic(errors.New("caCert did not contain any certificates"))
		}
		fmt.Printf("echoclient: added cert=%s as the trusted certificate\n", *trustedRootPath)
	}

	inputs := []io.Reader{os.Stdin}
	var clientSessionCache tls.ClientSessionCache
	if *useSessionCache {
		// create the client session cache with the default capacity; make a second request
		clientSessionCache = tls.NewLRUClientSessionCache(0)
		inputs = append(inputs, bytes.NewBufferString("second example request\n"))
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: *insecureSkipVerify,
		RootCAs:            certPool,
		Certificates:       certificates,
		ClientSessionCache: clientSessionCache,
	}

	for _, input := range inputs {
		fmt.Printf("echoclient: connecting to %s useTLS:%t ...\n", *addr, *useTLS)
		var conn net.Conn
		var err error
		if *useTLS {
			if *insecureSkipVerify {
				fmt.Println("echoclient WARNING: using insecureSkipVerify")
			}
			tlsConn, err := tls.Dial("tcp", *addr, tlsConfig)
			conn = tlsConn
			if err != nil {
				panic(err)
			}
			if !tlsConn.ConnectionState().HandshakeComplete {
				err := tlsConn.Handshake()
				if err != nil {
					panic(err)
				}
			}

			// log if the session resumption worked to test the cache
			state := tlsConn.ConnectionState()
			fmt.Printf("echoclient resumed TLS session? %t\n", state.DidResume)
		} else {
			conn, err = net.Dial("tcp", *addr)
			if err != nil {
				panic(err)
			}
		}

		fmt.Printf("echoclient: reading from stdin ...\n")
		inputScanner := bufio.NewScanner(input)
		connScanner := bufio.NewScanner(conn)
		for inputScanner.Scan() {
			fmt.Printf("echoclient: writing to server ...\n")

			lineWithNewLine := append(inputScanner.Bytes(), '\n')
			_, err = conn.Write(lineWithNewLine)
			if err != nil {
				panic(err)
			}
			fmt.Printf("echoclient: reading from server ...\n")
			if !connScanner.Scan() {
				panic("unexpected end of data from server")
			}
			if connScanner.Err() != nil {
				panic(connScanner.Err())
			}
			fmt.Printf("echoclient received from server: %s\n", connScanner.Text())
		}
		if inputScanner.Err() != nil {
			panic(inputScanner.Err())
		}

		err = conn.Close()
		if err != nil {
			panic(err)
		}
		fmt.Printf("echoclient: connection closed\n")
	}
}

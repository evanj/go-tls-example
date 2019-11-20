package main

import (
	"bufio"
	"crypto/tls"
	"net"
	"os"

	// "crypto/tls"
	// "crypto/x509"
	// "errors"
	"flag"
	"fmt"
	// "io/ioutil"
)

// func makeRequest(addr string, config *tls.Config) error {
// 	c, err := tls.Dial("tcp", addr, config)
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("writing...")
// 	_, err = c.Write([]byte("hello world\n"))
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("reading...")
// 	output, err := ioutil.ReadAll(c)
// 	if err != nil {
// 		return err
// 	}
// 	fmt.Println("read:", string(output))
// 	return c.Close()
// }

func main() {
	addr := flag.String("addr", "localhost:7000", "echo server address")
	useTLS := flag.Bool("useTLS", true, "Use TLS. If false, uses an unencrypted TCP connection")
	// testSessionTickets := flag.Bool("testSessionTickets", false, "Enable session cache and make a second request to test session resumption")
	insecureSkipVerify := flag.Bool("insecureSkipVerify", false, "skips verifying the server's certificate")
	// trustServer := flag.Bool("trustServer", false, "If true, trusts the server certificate")
	// clientCertificate := flag.Int("clientCert", -1, "If true, skips verifying the server")
	// trustedRootPath := flag.String("trustedRoot", "", "path to a trusted root certificate")
	flag.Parse()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: *insecureSkipVerify,
	}

	fmt.Printf("echoclient: connecting to %s useTLS:%t ...\n", *addr, *useTLS)
	var conn net.Conn
	var err error
	if *useTLS {
		if *insecureSkipVerify {
			fmt.Println("echoclient WARNING: using insecureSkipVerify")
		}
		conn, err = tls.Dial("tcp", *addr, tlsConfig)
	} else {
		conn, err = net.Dial("tcp", *addr)
	}
	if err != nil {
		panic(err)
	}

	fmt.Printf("echoclient: reading from stdin ...\n")
	stdinScanner := bufio.NewScanner(os.Stdin)
	connScanner := bufio.NewScanner(conn)
	for stdinScanner.Scan() {
		fmt.Printf("echoclient: writing to server ...\n")

		lineWithNewLine := append(stdinScanner.Bytes(), '\n')
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
	if stdinScanner.Err() != nil {
		panic(stdinScanner.Err())
	}

	err = conn.Close()
	if err != nil {
		panic(err)
	}
	fmt.Printf("echoclient: connection closed\n")
}

// certificates := []tls.Certificate{}
// if *clientCertificate >= 0 {
// 	if *clientCertificate >= len(clientCerts) {
// 		panic("clientCert out of range")
// 	}
// 	pair := clientCerts[*clientCertificate]
// 	cert, err := tls.X509KeyPair([]byte(pair[0]), []byte(pair[1]))
// 	if err != nil {
// 		panic(err)
// 	}
// 	certificates = []tls.Certificate{cert}
// 	fmt.Println("added a client certificate", cert.Leaf)
// }

// var certPool *x509.CertPool
// if *trustServer {
// 	// TODO: This does not work: The server's certificate does not specify host "localhost"
// 	certPool = x509.NewCertPool()
// 	ok := certPool.AppendCertsFromPEM([]byte(caCert))
// 	if !ok {
// 		panic(errors.New("caCert did not contain any certificates"))
// 	}
// 	fmt.Println("added our own CA to the trusted certificate pool")
// }

// config := &tls.Config{
// 	InsecureSkipVerify: *insecureSkipVerify,
// 	Certificates:       certificates,
// 	RootCAs:            certPool,
// }

// if *testSessionTickets {
// 	config.ClientSessionCache = tls.NewLRUClientSessionCache(0)
// 	fmt.Println("enabled ClientSessionCache")
// }

// err := makeRequest(*addr, config)
// if err != nil {
// 	panic(err)
// }

// // make a second request: ideally this should resume the session
// if *testSessionTickets {
// 	fmt.Println("making second request to test session resumption ...")
// 	err = makeRequest(*addr, config)
// 	if err != nil {
// 		panic(err)
// 	}
// }
// }

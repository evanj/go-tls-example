package cmdline

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

type ClientConfig struct {
	UseTLS          bool
	UseSessionCache bool
	TLSConfig       *tls.Config
	Addr            string
}

type Logf func(message string, args ...interface{})

func PrefixLogf(prefix string) Logf {
	return func(message string, args ...interface{}) {
		fmt.Printf(prefix+message, args...)
	}
}

// Returns the *Config from command line arguments.
func ParseClient(logf Logf) (*ClientConfig, error) {
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
			return nil, err
		}
		certificates = []tls.Certificate{cert}
		logf("using client cert=%s key=%s\n", *clientCertPath, *clientKeyPath)
	}

	var certPool *x509.CertPool
	if *trustedRootPath != "" {
		certBytes, err := ioutil.ReadFile(*trustedRootPath)
		if err != nil {
			return nil, err
		}

		certPool = x509.NewCertPool()
		ok := certPool.AppendCertsFromPEM(certBytes)
		if !ok {
			return nil, errors.New("trustedRootPath did not contain any certificates")
		}
		logf("added cert=%s as the trusted certificate\n", *trustedRootPath)
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

	return &ClientConfig{
		*useTLS,
		*useSessionCache,
		tlsConfig,
		*addr,
	}, nil
}

type ServerConfig struct {
	Addr      string
	TLSConfig *tls.Config
}

func ParseServer(logf Logf) (*ServerConfig, error) {
	addr := flag.String("addr", "localhost:7000", "listen address")
	certPath := flag.String("cert", "", "path to the server cert")
	keyPath := flag.String("key", "", "path to the server key")
	clientCARootCertPath := flag.String("clientCARootCert", "",
		"Path to the root CA certificate to verify client certs")
	flag.Parse()

	config := &ServerConfig{
		Addr: *addr,
	}

	if *certPath != "" {
		cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
		if err != nil {
			return nil, err
		}

		var certPool *x509.CertPool
		clientAuth := tls.NoClientCert
		if *clientCARootCertPath != "" {
			certBytes, err := ioutil.ReadFile(*clientCARootCertPath)
			if err != nil {
				return nil, err
			}

			certPool = x509.NewCertPool()
			ok := certPool.AppendCertsFromPEM(certBytes)
			if !ok {
				return nil, errors.New("cacert did not contain any certificates")
			}
			clientAuth = tls.RequireAndVerifyClientCert
			logf("requiring cert=%s for verifying client certificates\n", *clientCARootCertPath)
		}

		config.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    certPool,
			ClientAuth:   clientAuth,
		}
	}

	return config, nil
}

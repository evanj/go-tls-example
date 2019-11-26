package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/evanj/go-tls-example/cmdline"
)

func main() {
	config, err := cmdline.ParseClient(cmdline.PrefixLogf("echoclient: "))
	if err != nil {
		panic(err)
	}

	inputs := []io.Reader{os.Stdin}
	if config.UseSessionCache {
		inputs = append(inputs, bytes.NewBufferString("second example request\n"))
	}

	for _, input := range inputs {
		fmt.Printf("echoclient: connecting to %s useTLS:%t ...\n", config.Addr, config.UseTLS)
		var conn net.Conn
		var err error
		if config.UseTLS {
			if config.TLSConfig.InsecureSkipVerify {
				fmt.Println("echoclient WARNING: using insecureSkipVerify")
			}
			tlsConn, err := tls.Dial("tcp", config.Addr, config.TLSConfig)
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
			conn, err = net.Dial("tcp", config.Addr)
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

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

const localhostAddr = "localhost"
const startupConnectSleep = 100 * time.Millisecond
const startupTotalDuration = 2 * time.Second

const echoclientInput = "hello world\n"
const expectedSuccessOutput = "echoclient received from server: " + echoclientInput

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

type testConfiguration struct {
	name           string
	clientArgs     []string
	serverArgs     []string
	expectedOutput string
	expectFailure  bool
}

func runTest(
	echoclientPath string, echoserverPath string, listenAddr string, config *testConfiguration,
) error {
	fmt.Printf("starting server listening on %s ...\n", listenAddr)
	serverArgs := append([]string{"--addr=" + listenAddr}, config.serverArgs...)
	serverProc := exec.Command(echoserverPath, serverArgs...)
	serverProc.Stdout = os.Stdout
	serverProc.Stderr = os.Stderr
	err := serverProc.Start()
	if err != nil {
		return err
	}
	// ensure we stop the server
	defer serverProc.Process.Kill()

	// check that it has actually started
	now := time.Now()
	end := now.Add(startupTotalDuration)
	for time.Now().Before(end) {
		time.Sleep(startupConnectSleep)
		conn, err := net.Dial("tcp", listenAddr)
		if err != nil {
			if isConnRefused(err) {
				// try again if the connection was refused: server has not started yet
				continue
			}
			return err
		}

		// success the server exists!
		conn.Close()
		break
	}

	fmt.Printf("starting client ...\n")
	clientArgs := append([]string{"--addr=" + listenAddr}, config.clientArgs...)
	clientProc := exec.Command(echoclientPath, clientArgs...)
	clientProc.Stdin = bytes.NewBufferString(echoclientInput)
	output, err := clientProc.CombinedOutput()
	fmt.Println("=== start echoclient output ===")
	os.Stdout.Write(output)
	fmt.Println("=== end echoclient output ===")
	if err != nil {
		exitErr := &exec.ExitError{}
		if errors.As(err, &exitErr) && config.expectFailure {
			fmt.Printf("expected exit failure: %s\n", exitErr.Error())
		} else {
			return err
		}
	}
	if !bytes.Contains(output, []byte(config.expectedOutput)) {
		return errors.New("echoclient did not contain expected output")
	}
	return nil
}

func main() {
	echoclientPath := flag.String("echoclientPath", "", "path to the echoclient binary")
	echoserverPath := flag.String("echoserverPath", "", "path to the echoserver binary")
	serverCertPath := flag.String("serverCertPath", "", "path to the server certificate")
	serverKeyPath := flag.String("serverKeyPath", "", "path to the server key")
	localhostPort := flag.Int("localhostPort", 7123, "port to listen on locally")
	flag.Parse()

	listenAddr := fmt.Sprintf("%s:%d", localhostAddr, *localhostPort)
	fmt.Printf("using listenAddr=%s\n", listenAddr)

	serverCertKeyArgs := []string{"--cert=" + *serverCertPath, "--key=" + *serverKeyPath}

	configs := []*testConfiguration{
		{"no TLS (plain TCP)", []string{"--useTLS=false"}, []string{}, expectedSuccessOutput, false},

		// client fails due to not using TLS
		{"server TLS; client no TLS", []string{"--useTLS=false"}, serverCertKeyArgs,
			"panic: unexpected end of data from server", true},

		// client fails due to using global trusted root CAs
		{"server TLS; client global trusted TLS", []string{}, serverCertKeyArgs,
			"panic: x509: certificate signed by unknown authority", true},

		// client trusts any server
		{"server TLS; client global trusted TLS", []string{"--insecureSkipVerify"}, serverCertKeyArgs,
			expectedSuccessOutput, false},
	}

	for i, config := range configs {
		fmt.Printf("starting test %d %s; client=%s server=%s ...\n",
			i, config.name, strings.Join(config.clientArgs, " "), strings.Join(config.serverArgs, " "))
		err := runTest(*echoclientPath, *echoserverPath, listenAddr, config)
		if err != nil {
			fmt.Printf("TEST FAILED: %s\n", err.Error())
			os.Exit(42)
		}
		fmt.Printf("SUCCESS\n\n")
	}
}

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"
)

const localhostAddr = "localhost"
const startupConnectSleep = 100 * time.Millisecond
const startupTotalDuration = 2 * time.Second

const echoclientInput = "hello world\n"
const expectedEchoclientOutput = "echoclient received from server: " + echoclientInput

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func main() {
	echoclientPath := flag.String("echoclientPath", "", "path to the echoclient binary")
	echoserverPath := flag.String("echoserverPath", "", "path to the echoserver binary")
	localhostPort := flag.Int("localhostPort", 7123, "port to listen on locally")
	flag.Parse()

	listenAddr := fmt.Sprintf("%s:%d", localhostAddr, *localhostPort)
	fmt.Printf("starting server listening on %s ...\n", listenAddr)
	serverProc := exec.Command(*echoserverPath, "--useTLS=false", "--addr="+listenAddr)
	serverProc.Stdout = os.Stdout
	serverProc.Stderr = os.Stderr
	err := serverProc.Start()
	if err != nil {
		panic(err)
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
			panic(err)
		}

		// success the server exists!
		conn.Close()
		break
	}

	fmt.Printf("starting client ...\n")
	clientProc := exec.Command(*echoclientPath, "--useTLS=false", "--addr="+listenAddr)
	clientProc.Stdin = bytes.NewBufferString(echoclientInput)
	output, err := clientProc.CombinedOutput()
	fmt.Println("=== start echoclient output ===")
	os.Stdout.Write(output)
	fmt.Println("=== end echoclient output ===")
	if err != nil {
		panic(err)
	}
	if !bytes.Contains(output, []byte(expectedEchoclientOutput)) {
		panic("echoclient did not contain expected output")
	}
}

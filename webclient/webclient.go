package main

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/evanj/go-tls-example/cmdline"
)

func main() {
	config, err := cmdline.ParseClient(cmdline.PrefixLogf("webclient: "))
	if err != nil {
		panic(err)
	}

	transport := &http.Transport{
		TLSClientConfig: config.TLSConfig,
	}
	httpClient := &http.Client{Transport: transport}

	proto := "http"
	if config.UseTLS {
		proto = "https"
	}
	url := fmt.Sprintf("%s://%s/", proto, config.Addr)
	fmt.Printf("GET %s ...\n", url)
	resp, err := httpClient.Get(url)
	if err != nil {
		panic(err)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("body: %#v\n", string(bodyBytes))
	err = resp.Body.Close()
	if err != nil {
		panic(err)
	}
}

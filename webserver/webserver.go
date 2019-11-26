package main

import (
	"log"
	"net/http"

	"github.com/evanj/go-tls-example/cmdline"
)

func rootHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("%s %s", r.Method, r.URL.String())
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/plain;charset=utf-8")
	w.Write([]byte("hello!\n"))
}

func main() {
	config, err := cmdline.ParseServer(cmdline.PrefixLogf("webserver: "))
	if err != nil {
		panic(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", rootHandler)

	server := &http.Server{
		Addr:      config.Addr,
		Handler:   mux,
		TLSConfig: config.TLSConfig,
	}

	if server.TLSConfig == nil {
		log.Printf("listening on http://%s", server.Addr)
		err = server.ListenAndServe()
	} else {
		log.Printf("listening on https://%s", server.Addr)
		err = server.ListenAndServeTLS("", "")
	}
	if err != nil {
		panic(err)
	}
}

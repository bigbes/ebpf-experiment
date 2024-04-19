package main

import (
	"io"
	"net/http"
)

func echoHandle(rw http.ResponseWriter, r *http.Request) {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		rw.Header().Set("Content-Type", ct)
	}

	bytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Write(bytes)
	rw.Write([]byte("\n"))
}

func main() {
	http.HandleFunc("/", echoHandle)
	// err := http.ListenAndServe(":8443", nil)
	err := http.ListenAndServeTLS(":8443", "./server.pem", "./server.pem", nil)
	if err != http.ErrServerClosed {
		panic("failed to start server")
	}
}

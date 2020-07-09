package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/log", serverLogs)
	log.Println("listening on 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Println(err)
	}
}

func serverLogs(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open("/etc/debug.txt")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, err)
		return
	}
	io.Copy(w, f)
	f.Close()
}

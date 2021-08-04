package main

import (
	"fmt"
	"log"
	"net/http"

	"sampleGLogin/handlers"
)

func main() {
	server := &http.Server{
		Addr:    fmt.Sprintf(":9001"),
		Handler: handlers.New(),
	}

	log.Printf("Start HTTP Server. Listening at %q", server.Addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Printf("%v", err)
	} else {
		log.Println("Server closed!")
	}
}

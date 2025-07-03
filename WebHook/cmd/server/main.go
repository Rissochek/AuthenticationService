package main

import (
	"fmt"
	"log"
	"net/http"
	"io"

	"AuthService/source/utils"
)

func handler(w http.ResponseWriter, r *http.Request) {
	msg_body, _ := io.ReadAll(r.Body)
	fmt.Printf("Получено сообщение: %v", string(msg_body))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	utils.LoadEnvFile()
	port := utils.GetKeyFromEnv("WEBHOOK_PORT")
	http.HandleFunc("/webhook", handler)
	log.Printf("Server is listening on: %v", port)
	http.ListenAndServe(fmt.Sprintf(":%v", port), nil)
}
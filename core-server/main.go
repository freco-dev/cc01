package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/freco-dev/cc01/core-server/config"
)

func main() {
	var (
		conf   config.Config
		server CC01Server
	)

	err := conf.Load()
	if err != nil {
		log.Fatalf("failed to load conf: %v", err)
	}

	err = server.Init(conf)
	if err != nil {
		log.Fatalf("failed to init cc01 %v", err)
	}

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

	server.Start()
	defer server.Stop()

	<-signalChan
}

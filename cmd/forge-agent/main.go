package main

import (
	"log"
	"net/http"

	"github.com/Jina404/forge/pkg/api"
	"github.com/Jina404/forge/pkg/config"
	"github.com/Jina404/forge/pkg/storage"
)

func main() {
	cfg := config.FromEnv()
	var server *api.Server

	if cfg.UsePostgres && cfg.DatabaseURL != "" {
		postgresStore, err := storage.NewPostgresStore(cfg.DatabaseURL)
		if err != nil {
			log.Fatalf("failed to initialize postgres store: %v", err)
		}
		if err := postgresStore.InitSchema(); err != nil {
			log.Fatalf("failed to initialize postgres schema: %v", err)
		}
		defer func() {
			_ = postgresStore.Close()
		}()
		server = api.NewServerWithConfig(cfg, postgresStore)
	} else {
		server = api.NewServerWithConfig(cfg, storage.NewInMemoryStore())
	}

	log.Printf("forge-agent control API listening on %s", cfg.APIBindAddress)
	if err := http.ListenAndServe(cfg.APIBindAddress, server.Handler()); err != nil {
		log.Fatal(err)
	}
}

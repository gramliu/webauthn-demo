package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gramliu/webauthn-demo/backend/internal/demo"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/joho/godotenv"
)

func main() {
	for _, file := range []string{"../.env.development.local", "../.env.local", ".env.local"} {
		_ = godotenv.Load(file)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dbURL := os.Getenv("DATABASE_URL")
	if len(os.Args) > 1 && os.Args[1] == "migrate" && os.Getenv("DATABASE_URL_UNPOOLED") != "" {
		dbURL = os.Getenv("DATABASE_URL_UNPOOLED")
	}
	if dbURL == "" {
		log.Fatal("DATABASE_URL is required; connect Neon and pull development environment variables")
	}
	store, err := demo.NewStore(ctx, dbURL)
	if err != nil {
		log.Fatal("Could not connect to Postgres")
	}
	defer store.Pool.Close()
	if len(os.Args) > 1 && os.Args[1] == "migrate" {
		if err = store.Migrate(ctx); err != nil {
			if pgErr, ok := err.(*pgconn.PgError); ok {
				log.Fatalf("Database migration failed: %s (%s)", pgErr.Message, pgErr.Code)
			}
			log.Fatal("Database migration failed")
		}
		log.Print("Database schema is ready")
		return
	}
	deployed := os.Getenv("VERCEL") == "1"
	executor, err := demo.NewExecutor(os.Getenv("EXECUTOR_PRIVATE_KEY"), !deployed)
	if err != nil {
		log.Fatal(err)
	}
	origin := os.Getenv("APP_ORIGIN")
	if deployed && os.Getenv("VERCEL_ENV") != "production" && os.Getenv("VERCEL_URL") != "" {
		origin = "https://" + os.Getenv("VERCEL_URL")
	}
	if origin == "" && os.Getenv("VERCEL_PROJECT_PRODUCTION_URL") != "" {
		origin = "https://" + os.Getenv("VERCEL_PROJECT_PRODUCTION_URL")
	}
	if origin == "" {
		origin = "http://localhost:5173"
	}
	server, err := demo.NewServer(store, executor, origin)
	if err != nil {
		log.Fatal(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Keyhold Go API listening on :%s (origin %s)", port, origin)
	httpServer := &http.Server{Addr: ":" + port, Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	log.Fatal(httpServer.ListenAndServe())
}

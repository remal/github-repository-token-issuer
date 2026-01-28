package main

import (
	"os"

	"github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
)

func main() {
	// Validate required environment variables at startup
	if os.Getenv("GITHUB_APP_ID") == "" {
		os.Exit(1)
	}

	// Register HTTP function
	functions.HTTP("TokenHandler", TokenHandler)

	// Start the Functions Framework
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if err := funcframework.Start(port); err != nil {
		os.Exit(1)
	}
}

package main

import (
	"os"

	"github.com/GoogleCloudPlatform/functions-framework-go/funcframework"
	"github.com/GoogleCloudPlatform/functions-framework-go/functions"
)

func init() {
	// Validate required environment variables at startup
	appID := os.Getenv("GITHUB_APP_ID")
	if appID == "" {
		os.Exit(1)
	}

	// Register HTTP function
	functions.HTTP("TokenHandler", TokenHandler)
}

func main() {
	// Start the Functions Framework
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	if err := funcframework.Start(port); err != nil {
		os.Exit(1)
	}
}

package server

import (
	"log"
	"os"

	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var oktaOauthConfig = &oauth2.Config{}

func Init() {

	godotenv.Load("./.okta.env")

	initSessionStore()

	issuer := os.Getenv("OKTA_OAUTH2_ISSUER")
	clientID := os.Getenv("OKTA_OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_OAUTH2_CLIENT_SECRET")

	if issuer == "" {
		log.Fatal("OKTA_OAUTH2_ISSUER environment variable is required")
	}
	if clientID == "" {
		log.Fatal("OKTA_OAUTH2_CLIENT_ID environment variable is required")
	}
	if clientSecret == "" {
		log.Fatal("OKTA_OAUTH2_CLIENT_SECRET environment variable is required")
	}

	redirectURL := os.Getenv("OKTA_OAUTH2_REDIRECT_URL")
	if redirectURL == "" {
		redirectURL = "http://localhost:8080/authorization-code/callback"
	}

	oktaOauthConfig = &oauth2.Config{
		RedirectURL:  redirectURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		Endpoint: oauth2.Endpoint{
			AuthURL:   issuer + "/v1/authorize",
			TokenURL:  issuer + "/v1/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080" // default when missing
	}

	// Set the router as the default one shipped with Gin
	router := gin.Default()

	// Serve HTML templates
	router.LoadHTMLGlob("./templates/*")
	// Serve frontend static files
	router.Use(static.Serve("/static", static.LocalFile("./static", true)))

	// setup public routes
	router.GET("/", IndexHandler)
	router.GET("/login", LoginHandler)
	router.GET("/authorization-code/callback", AuthCodeCallbackHandler)

	// setup private routes
	authorized := router.Group("/", AuthMiddleware())

	authorized.POST("/logout", LogoutHandler)
	authorized.GET("/profile", ProfileHandler)

	// Start and run the server
	log.Printf("Running on http://localhost:" + port)
	router.Run(":" + port)
}

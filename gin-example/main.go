package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"example.com/gin/hello"
	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var (
	domain = ""
	client = ""
)

func main() {
	provider, err := oidc.NewProvider(
		context.Background(),
		"https://"+domain+"/",
	)
	if err != nil {
		log.Fatalf("Failed to get provider: %v", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: client,
	})

	router := gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000"},
		AllowMethods:     []string{"OPTIONS", "GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	router.GET("/api/external", hello.CheckJWT(), func(ctx *gin.Context) {
		claims, ok := ctx.Request.Context().Value(jwtmiddleware.ContextKey{}).(*validator.ValidatedClaims)
		if !ok {
			ctx.AbortWithStatusJSON(
				http.StatusInternalServerError,
				map[string]string{"message": "Failed to get validated JWT claims."},
			)
			return
		}

		// u have to use this subject to get the user info from the database
		fmt.Println("Subject", claims.RegisteredClaims.Subject)

		err := claims.CustomClaims.Validate(ctx.Request.Context())
		if err != nil {
			fmt.Println("Error", err)
		}

		ctx.JSON(http.StatusOK, claims)
	})
	router.GET("/api/v1/auth0", func(ctx *gin.Context) {
		token := ctx.Query("token")
		if token == "" {
			ctx.JSON(http.StatusBadRequest, "No token provided")
			return
		}

		idToken, err := verifier.Verify(ctx.Request.Context(), token)
		if err != nil {
			ctx.String(http.StatusInternalServerError, "Failed to verify ID Token.")
			return
		}

		var profile map[string]interface{}
		if err := idToken.Claims(&profile); err != nil {
			ctx.String(http.StatusInternalServerError, err.Error())
			return
		}

		ctx.JSON(http.StatusOK, gin.H{
			"profile": profile,
		})
	})

	log.Print("Server listening on http://localhost:3001")
	if err := http.ListenAndServe("0.0.0.0:3001", router); err != nil {
		log.Fatalf("There was an error with the http server: %v", err)
	}

}

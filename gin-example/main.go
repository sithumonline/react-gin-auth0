package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"example.com/gin/hello"
	"github.com/Nerzal/gocloak/v13"
	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)

var (
	domain = ""
	client = ""

	kc_domain   = ""
	kc_user     = ""
	kc_password = ""
	kc_realm    = ""
	kc_client   = ""
)

var kd_instance = gocloak.NewClient(kc_domain)

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

	token, err := kd_instance.LoginAdmin(context.Background(), kc_user, kc_password, kc_realm)
	if err != nil {
		log.Fatalf("Failed to login: %v", err)
	}

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
	router.GET("/api/v1/oauth/auth0", func(ctx *gin.Context) {
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

		email, ok := profile["email"].(string)
		if !ok {
			ctx.String(http.StatusInternalServerError, "Failed to get email from profile.")
			return
		}

		// you can use this email to get the user info from the database
		// if the user is not in the database, you can create a new user
		fmt.Println("Email", email)

		ctx.JSON(http.StatusOK, gin.H{
			"profile": profile,
		})
	})
	router.POST("/api/v1/user", func(ctx *gin.Context) {
		// get the user request body
		var user map[string]interface{}
		if err := ctx.BindJSON(&user); err != nil {
			ctx.JSON(http.StatusBadRequest, "Invalid request body")
			return
		}

		fmt.Println("User", user)

		userId, ok := user["userId"].(string)
		if !ok {
			ctx.JSON(http.StatusBadRequest, "Invalid user id")
			return
		}

		userInfo, err := kd_instance.GetUserByID(ctx.Request.Context(), token.AccessToken, kc_realm, userId)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, "Failed to get user info")
			return
		}

		fmt.Println("UserInfo", userInfo)

		// send the user info as a response
		ctx.JSON(http.StatusOK, gin.H{
			"user": user,
			"info": userInfo,
		})
	})
	router.GET("/api/test-auth", KeycloakJWTMiddleware2(), func(ctx *gin.Context) {
		claims := ctx.MustGet("claims").(jwt.MapClaims)
		ctx.JSON(http.StatusOK, gin.H{
			"message": "You are authorized",
			"claims":  claims,
		})
	})

	log.Print("Server listening on http://localhost:3002")
	if err := http.ListenAndServe("0.0.0.0:3002", router); err != nil {
		log.Fatalf("There was an error with the http server: %v", err)
	}

}

func KeycloakJWTMiddleware2() gin.HandlerFunc {
	//kd_instance := gocloak.NewClient(kc_domain)
	issuerInfo, err := kd_instance.GetIssuer(context.Background(), kc_realm)
	if err != nil {
		log.Fatalf("Failed to get Keycloak public key: %v", err)
	}
	publicKey := *issuerInfo.PublicKey

	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader("Authorization")
		if authHeader == "" {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			base64Data := []byte("-----BEGIN PUBLIC KEY-----\n" + publicKey + "\n-----END PUBLIC KEY-----")
			return jwt.ParseRSAPublicKeyFromPEM(base64Data)
		})

		if err != nil || !token.Valid {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"message": "Invalid token", "error": err.Error()})
			return
		}

		ctx.Set("claims", claims)
		ctx.Next()
	}
}

package hello

import (
	"log"
	"net/http"
	"net/url"
	"time"

	jwtmiddleware "github.com/auth0/go-jwt-middleware/v2"
	"github.com/auth0/go-jwt-middleware/v2/jwks"
	"github.com/auth0/go-jwt-middleware/v2/validator"
	"github.com/gin-gonic/gin"
)

/*
var (
	// The signing key for the token.
	signingKey = []byte("TLoYEH4SS2cUF7P2EbRqmg39jtaRqEvxlcktA7s74eGGoq-Q4rLKXMXE3pfdYH7m")

	// The issuer of our token.
	issuer = "https://dev-8ls3xxkekz2uw215.us.auth0.com/"

	// The audience of our token.
	audience = []string{"https://dev-8ls3xxkekz2uw215.us.auth0.com/api/v2/"}

	// Our token must be signed using this data.
	keyFunc = func(ctx context.Context) (interface{}, error) {
		return signingKey, nil
	}

	// We want this struct to be filled in with
	// our custom claims from the token.
	customClaims = func() validator.CustomClaims {
		return &CustomClaimsExample{}
	}
)
*/

var (
	domain       = "dev-8ls3xxkekz2uw215.us.auth0.com"
	audience     = []string{"https://dev-8ls3xxkekz2uw215.us.auth0.com/api/v2/"}
	customClaims = func() validator.CustomClaims {
		return &CustomClaimsExample{}
	}
)

// checkJWT is a gin.HandlerFunc middleware
// that will check the validity of our JWT.
func CheckJWT() gin.HandlerFunc {
	issuerURL, err := url.Parse("https://" + domain + "/")
	if err != nil {
		log.Fatalf("Failed to parse the issuer url: %v", err)
	}

	provider := jwks.NewCachingProvider(issuerURL, 5*time.Minute)

	// Set up the validator.
	jwtValidator, err := validator.New(
		provider.KeyFunc,
		validator.RS256,
		issuerURL.String(),
		audience,
		validator.WithCustomClaims(customClaims),
		validator.WithAllowedClockSkew(30*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to set up the validator: %v", err)
	}

	errorHandler := func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Encountered error while validating JWT: %v", err)
	}

	middleware := jwtmiddleware.New(
		jwtValidator.ValidateToken,
		jwtmiddleware.WithErrorHandler(errorHandler),
	)

	return func(ctx *gin.Context) {
		encounteredError := true
		var handler http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
			encounteredError = false
			ctx.Request = r
			ctx.Next()
		}

		middleware.CheckJWT(handler).ServeHTTP(ctx.Writer, ctx.Request)

		if encounteredError {
			ctx.AbortWithStatusJSON(
				http.StatusUnauthorized,
				map[string]string{"message": "JWT is invalid."},
			)
		}
	}
}

package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/joho/godotenv"
)

var (
	authDomain   string
	authAudience string
	aud          string
)

func init() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("No .env file found")
	}

	fmt.Println(os.Getenv("AUTH0_AUDIENCE"))
	authDomain = "dev-8qs326yu7f2mbnky.us.auth0.com" // os.Getenv("AUTH0_DOMAIN")
	authAudience = "https://api-fisccloud"
	aud = "mgxvQpqQqAXTxZtQQ39dM92z5nYpvpyD" // os.Getenv("AUTH0_AUDIENCE")
}

type JWKs struct {
	Keys []struct {
		Kty string   `json:"kty"`
		Kid string   `json:"kid"`
		Use string   `json:"use"`
		N   string   `json:"n"`
		E   string   `json:"e"`
		X5c []string `json:"x5c"`
	} `json:"keys"`
}

var jwks *JWKs
var once sync.Once

func getJWKs() (*JWKs, error) {
	var err error
	once.Do(func() {
		resp, err := http.Get(fmt.Sprintf("https://%s/.well-known/jwks.json", authDomain))
		if err != nil {
			return
		}
		defer resp.Body.Close()

		var jwkSet JWKs
		if err = json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
			return
		}
		jwks = &jwkSet
	})
	return jwks, err
}

func getPemCert(token *jwt.Token) (string, error) {
	jwks, err := getJWKs()
	if err != nil {
		return "", err
	}

	for _, key := range jwks.Keys {
		if key.Kid == token.Header["kid"] {
			return fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----", key.X5c[0]), nil
		}
	}
	return "", fmt.Errorf("unable to find appropriate key")
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			cert, err := getPemCert(token)
			if err != nil {
				return nil, err
			}
			return jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		})

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if !claims.VerifyAudience(aud, false) && !claims.VerifyAudience(authAudience, false) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid audience"})
				c.Abort()
				return
			}

			if !claims.VerifyIssuer(fmt.Sprintf("https://%s/", authDomain), false) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid issuer"})
				c.Abort()
				return
			}

			c.Set("user", claims)
			c.Next()
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
		}
	}
}

func RoleMiddleware(requiredRole []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userClaims, exists := c.Get("user")
		if !exists {
			c.JSON(http.StatusForbidden, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		claims := userClaims.(jwt.MapClaims)
		roles, ok := claims[fmt.Sprintf("%s/roles", authAudience)].([]interface{})
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid roles"})
			c.Abort()
			return
		}

		hasRole := false
		for _, role := range roles {
			for _, v := range requiredRole {
				if role == v {
					hasRole = true
					break
				}
			}
		}

		if !hasRole {
			c.JSON(http.StatusForbidden, gin.H{"error": "operation not allowed"})
			c.Abort()
			return
		}
		c.Set("role", requiredRole)
		c.Next()
	}
}

func GetClaims(c *gin.Context) jwt.MapClaims {
	data := c.Keys
	for _, value := range data {
		switch v := value.(type) {
		case jwt.Claims:
			return v.(jwt.MapClaims)
		}
	}
	return nil
}

package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/milktech-io/auth-middleware/auth"
)

func main() {
	r := gin.Default()

	r.GET("/public-endpoint", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, this is a public endpoint"})
	})

	r.GET("/secure-endpoint", auth.AuthMiddleware(), func(c *gin.Context) {
		user, _ := c.Get("user")
		c.JSON(http.StatusOK, gin.H{"message": "Hello, this is a secure endpoint", "user": user})
	})

	r.GET("/admin-endpoint", auth.AuthMiddleware(), auth.RoleMiddleware([]string{"admin"}), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Hello, this is an admin endpoint"})
	})

	r.Run(":8080")
}

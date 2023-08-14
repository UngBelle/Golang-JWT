package middleware

import (
	"fmt"
	"jwt-golang/initializers"
	"jwt-golang/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func Authorization(c *gin.Context) {
	// Get the cookie off the request
	tokenString, err := c.Cookie("Authorization")
	// fmt.Println(tokenString)
	if err != nil {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
	// Parse takes the token string and a function for looking up the key. The latter is especially
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET_KEY")), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Check the expiration
		if float64(time.Now().Unix()) > claims["expire"].(float64) {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		// Find the user with token user
		var user models.Users
		fmt.Println(&user)
		fmt.Print(claims["subject"])
		// initializers.DB.Find(&users, "email = ?", user.Email)
		// initializers.DB.First(&user, { email: claims["subject"] } )
		initializers.DB.First(&user, "email = ?", claims["subject"])
		// if user.Email == "" {
		// 	c.AbortWithStatus(http.StatusUnauthorized)
		// }
		// Attach to request
		c.Set("user", user)
		// Continue
		c.Next()

	} else {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

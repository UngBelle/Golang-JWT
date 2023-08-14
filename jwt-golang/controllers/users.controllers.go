package controllers

import (
	"jwt-golang/initializers"
	"jwt-golang/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func SignUp(c *gin.Context) {
	// Get the email/password
	var user struct {
		Name     string
		Email    string
		Password string
	}
	if c.Bind(&user) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to get user",
		})

		return
	}

	// Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash password",
		})

		return
	}
	// Create a user
	users := models.Users{
		Name:     user.Name,
		Email:    user.Email,
		Password: string(hash),
	}

	result := initializers.DB.Create(&users)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create user",
		})

		return
	}

	// Respond to user
	c.JSON(http.StatusOK, gin.H{
		"users":   users,
		"message": "User is created successfully",
	})
}

func SignIn(c *gin.Context) {
	// Get the email/password
	var user struct {
		Name     string
		Email    string
		Password string
	}
	if c.Bind(&user) != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to get user",
		})
		return
	}

	// Retrieve the email/password user
	var users models.Users
	initializers.DB.Find(&users, "email = ?", user.Email)

	if user.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email",
		})
		return
	}

	// Compare the sent in password
	err := bcrypt.CompareHashAndPassword([]byte(users.Password), []byte(user.Password))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid password",
		})

		return
	}

	// Generate a jwt token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"subject": user.Email,
		"expire":  time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a tring using the secret key
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET_KEY")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid token",
		})

		return
	}

	// Send it back
	// Set Cookie
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("Authorization", tokenString, 3600*24*30, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"token":   tokenString,
		"message": "User signed in and token generated successfully",
	})
}

func Validation(c *gin.Context) {
	// user, _ := c.Get("user")

	c.JSON(http.StatusOK, gin.H{
		"message": "The user is validated, and can be logged in",
	})
}

package main

import (
	"jwt-golang/controllers"
	"jwt-golang/initializers"
	"jwt-golang/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDatabase()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/signup", controllers.SignUp)
	r.POST("/signin", controllers.SignIn)
	r.GET("/validation", middleware.Authorization, controllers.Validation)

	r.Run()
}

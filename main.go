package main

import (
	"jwt-auth-gin-gonic/controllers"
	"jwt-auth-gin-gonic/database"
	routes "jwt-auth-gin-gonic/routes"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// load the .env file
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("error loading .env file")
	}

	// read from env var
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// intialize DB connection
	database.InitDBConn()

	// initialize user collection
	controllers.InitUserCollection()

	// initialize user struct validator
	controllers.InitValidator()

	router := gin.New()
	router.Use(gin.Logger())

	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	router.GET("/api-1", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "Access granted for api-1"})
	})

	router.GET("/api-2", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "Access granted for api-2"})
	})

	router.Run(":" + port)
}

package main

import (
	"api/src/config"
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres" // postgres dialect

	"api/src/controllers/user"
)

func main() {
	// load config
	if err := config.LoadConfig("./config"); err != nil {
		panic(fmt.Errorf("Invalid application configuration: %s", err))
	}

	// open db connection
	config.Config.Db, config.Config.DbErr = gorm.Open("postgres", config.Config.DbDsn)
	defer config.Config.Db.Close()
	if config.Config.DbErr != nil {
		fmt.Print(config.Config.DbErr)
	}

	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.GET("/users", user.Index)
	r.POST("/users", user.Create)
	r.GET("/users/:id", user.Get)
	r.PUT("/users/:id", user.Put)
	r.PATCH("/users/:id/password", user.UpdatePasswordAuthenticated)
	r.PATCH("/users/:id/password/:token", user.UpdatePasswordReset)
	r.DELETE("/users/:id", user.Delete)

	r.Run(config.Config.Port)
}

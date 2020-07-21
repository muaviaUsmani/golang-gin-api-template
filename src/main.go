package main

import (
	"api/src/config"
	"api/src/middleware"
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
	r.Use(middleware.CORS())

	r.Group("/guest")
	{
		r.POST("/signup", user.Signup)
		r.POST("/login", user.Login)

		r.PATCH("/users/:id/password/:token", user.UpdatePasswordReset)
	}

	r.Group("/authorized")
	{
		r.Use(middleware.Authorized())

		r.POST("/logout", user.Logout)

		r.GET("/users", user.Index)
		r.POST("/users", user.Create)
		r.GET("/users/:id", user.Get)
		r.PUT("/users/:id", user.Put)
		r.PATCH("/users/:id/password", user.UpdatePasswordAuthenticated)
		r.DELETE("/users/:id", user.Delete)
	}

	r.Run(config.Config.Port)
}

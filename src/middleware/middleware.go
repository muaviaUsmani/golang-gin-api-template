package middleware

import (
	"api/src/config"
	"api/src/helpers"
	"api/src/models/user"
	"errors"
	"fmt"

	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"
)

type requestHeader struct {
	Authorization string `header:"Authorization"`
	ApiKey        string `header:"x-api-key"`
}

// Authorized checks if request has token or API key
func Authorized() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		headers := requestHeader{}
		ctx.BindHeader(&headers)
		queryToken := ctx.Query("token")
		queryApiKey := ctx.Query("key")

		if headers.Authorization != "" || queryToken != "" {
			var token string
			if headers.Authorization != "" {
				token = headers.Authorization
			} else {
				token = queryToken
			}
			owner, err := validateToken(token)
			fmt.Println(owner)
			if err.Code != 0 {
				ctx.AbortWithStatusJSON(err.Code, gin.H{"message": err.Message})
			}

			publicUser := new(user.PublicUser)
			copier.Copy(publicUser, &owner)
			ctx.Set("user", publicUser)
		} else if headers.ApiKey != "" || queryApiKey != "" {

		} else {
			ctx.AbortWithStatusJSON(401, gin.H{"message": "No access token or API key provided."})
		}
		ctx.Next()
	}
}

// CORS adds cors middleware to every request
func CORS() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Writer.Header().Add("Access-Control-Allow-Origin", "*")
		ctx.Writer.Header().Set("Access-Control-Max-Age", "86400")
		ctx.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		ctx.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		ctx.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		ctx.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if ctx.Request.Method == "OPTIONS" {
			ctx.AbortWithStatus(200)
		} else {
			ctx.Next()
		}
	}
}

func validateToken(token string) (*user.User, helpers.HTTPError) {
	var errorDetails helpers.HTTPError
	owner := new(user.User)

	token = strings.Replace(token, "Bearer ", "", -1)
	// parse token
	parsedToken, err := jwt.ParseWithClaims(token, &user.CustomAccessToken{}, func(t *jwt.Token) (interface{}, error) {
		return []byte(config.Config.AppKey), nil
	})
	if err != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return owner, errorDetails
	}
	if claims, ok := parsedToken.Claims.(*user.CustomAccessToken); ok && parsedToken.Valid {
		fetchErr := config.Config.Db.Where("id=? AND token=?", claims.ID, token).First(&owner).Error
		if fetchErr != nil {
			if owner.ID == "" {
				errorDetails = helpers.HTTPError{Code: 401, Message: "Access token is invalid.", Error: errors.New("Access token is invalid.")}
				return owner, errorDetails
			}
			errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
			return owner, errorDetails
		}
	} else {
		errorDetails = helpers.HTTPError{Code: 401, Message: "Access token is invalid.", Error: errors.New("Access token is invalid.")}
		return owner, errorDetails
	}
	return owner, errorDetails
}

package user

import (
	"api/src/models/user"

	"github.com/gin-gonic/gin"
)

type userResource struct {
	ID string `uri:"id" binding:"required,uuid"`
}

type forgotPasswordResource struct {
	ID         string `uri:"id" binding:"required,uuid"`
	ResetToken string `uri:"token" binding:"required"`
}

// Index fetches all users
func Index(ctx *gin.Context) {
	userData, err := user.Index()
	if err.Code != 0 {
		ctx.JSON(err.Code, gin.H{
			"message": err.Message,
		})
		return
	}
	ctx.JSON(200, userData)
}

// Create adds a new user resource
func Create(ctx *gin.Context) {
	var userJson user.User
	if ctx.ShouldBind(&userJson) == nil {
		var createdUser *user.AuthenticatedUser

		createdUser, err := user.Create(&userJson)
		if err.Code != 0 {
			ctx.JSON(err.Code, gin.H{
				"message": err.Message,
			})
			return
		}
		ctx.JSON(200, &createdUser)
	}
}

// Get fetches the user by given ID
func Get(ctx *gin.Context) {
	var uresource userResource

	if err := ctx.ShouldBindUri(&uresource); err != nil {
		ctx.JSON(40, gin.H{"message": "User ID is required."})
		return
	}
	userData, userErr := user.Get(uresource.ID)
	if userErr.Code != 0 {
		ctx.JSON(userErr.Code, gin.H{"message": userErr.Message})
		return
	}
	ctx.JSON(200, userData)
}

// Put updates the user by given ID and returns the user
func Put(ctx *gin.Context) {
	var uresource userResource
	var userJson user.PublicUser

	if err := ctx.ShouldBindUri(&uresource); err != nil {
		ctx.JSON(403, gin.H{"message": "User ID is required."})
		return
	}
	if jsonErr := ctx.ShouldBind(&userJson); jsonErr != nil {
		ctx.JSON(403, gin.H{"message": "User data is invalid."})
		return
	}
	userData, err := user.Put(&userJson, uresource.ID)
	if err.Code != 0 {
		ctx.JSON(err.Code, gin.H{"message": err.Message})
		return
	}
	ctx.JSON(200, userData)
}

// UpdatePasswordAuthenticated patches the password for user given by ID
func UpdatePasswordAuthenticated(ctx *gin.Context) {
	var uresource userResource
	var passwordObject user.PasswordReplacement

	if err := ctx.ShouldBindUri(&uresource); err != nil {
		ctx.JSON(403, gin.H{"message": "User ID is required."})
		return
	}
	if jsonErr := ctx.ShouldBind(&passwordObject); jsonErr != nil {
		ctx.JSON(403, gin.H{"message": "Password data is invalid."})
		return
	}
	userData, updateErr := user.UpdatePasswordAuthenticated(&passwordObject, uresource.ID)
	if updateErr.Code != 0 {
		ctx.JSON(updateErr.Code, gin.H{"message": updateErr.Message})
		return
	}
	ctx.JSON(200, userData)
}

// UpdatePasswordReset patches the password for user given by token
func UpdatePasswordReset(ctx *gin.Context) {
	var uresource forgotPasswordResource
	var passwordObject user.PasswordReplacement

	if err := ctx.ShouldBindUri(&uresource); err != nil {
		ctx.JSON(403, gin.H{"message": err.Error()})
		return
	}
	if jsonErr := ctx.ShouldBind(&passwordObject); jsonErr != nil {
		ctx.JSON(403, gin.H{"message": "Password data is invalid."})
		return
	}
	userData, updateErr := user.UpdatePasswordReset(&passwordObject, uresource.ID, uresource.ResetToken)
	if updateErr.Code != 0 {
		ctx.JSON(updateErr.Code, gin.H{"message": updateErr.Message})
		return
	}
	ctx.JSON(200, userData)
}

// Delete destorys the user resource by given ID
func Delete(ctx *gin.Context) {
	var uresource userResource

	if err := ctx.ShouldBindUri(&uresource); err != nil {
		ctx.JSON(40, gin.H{"message": "User ID is required."})
		return
	}
	_, userErr := user.Delete(uresource.ID)
	if userErr.Code != 0 {
		ctx.JSON(userErr.Code, gin.H{"message": userErr.Message})
		return
	}
	ctx.JSON(200, gin.H{"success": true})
}

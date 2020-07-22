package user

import (
	UserDAO "api/src/daos/user"
	UserModel "api/src/models/user"

	"github.com/gin-gonic/gin"
	"github.com/jinzhu/copier"
)

type userResource struct {
	ID string `uri:"id" binding:"required,uuid"`
}

type forgotPasswordResource struct {
	ID         string `uri:"id" binding:"required,uuid"`
	ResetToken string `uri:"token" binding:"required"`
}

// Signup registers a new user
func Signup(ctx *gin.Context) {
	var signupData UserModel.SignupData
	if ctx.ShouldBind(&signupData) == nil {
		var createdUser *UserModel.AuthenticatedUser

		createdUser, err := UserDAO.Signup(&signupData)
		if err.Code != 0 {
			ctx.JSON(err.Code, gin.H{
				"message": err.Message,
			})
			return
		}

		ctx.JSON(200, &createdUser)
		return
	}
	ctx.JSON(401, gin.H{
		"message": "Required fields must be filled.",
	})
}

// Login authenticated a user given email and password
func Login(ctx *gin.Context) {
	var loginData UserModel.LoginData
	if ctx.ShouldBind(&loginData) == nil {
		var authenticatedUser *UserModel.AuthenticatedUser

		authenticatedUser, err := UserDAO.Login(&loginData)
		if err.Code != 0 {
			ctx.JSON(err.Code, gin.H{
				"message": err.Message,
			})
			return
		}

		ctx.JSON(200, &authenticatedUser)
		return
	}
	ctx.JSON(401, gin.H{
		"message": "Required fields must be filled.",
	})
}

// Logout invalidates the token for future use
func Logout(ctx *gin.Context) {
	storedUser := ctx.MustGet("user").(*UserModel.PublicUser)
	_, userErr := UserDAO.Logout(storedUser.ID)
	if userErr.Code != 0 {
		ctx.JSON(userErr.Code, gin.H{"message": userErr.Message})
		return
	}
	ctx.JSON(200, gin.H{"success": true})
}

// Index fetches all users
func Index(ctx *gin.Context) {
	userData, err := UserDAO.Index()
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
	var userJson UserModel.User
	if ctx.ShouldBind(&userJson) == nil {
		var createdUser *UserModel.User

		createdUser, err := UserDAO.Create(&userJson)
		if err.Code != 0 {
			ctx.JSON(err.Code, gin.H{
				"message": err.Message,
			})
			return
		}
		publicUser := new(UserModel.PublicUser)
		copier.Copy(publicUser, &createdUser)
		ctx.JSON(200, &publicUser)
	}
}

// Get fetches the user by given ID
func Get(ctx *gin.Context) {
	var uresource userResource

	if err := ctx.ShouldBindUri(&uresource); err != nil {
		ctx.JSON(40, gin.H{"message": "User ID is required."})
		return
	}
	userData, userErr := UserDAO.Get(uresource.ID)
	if userErr.Code != 0 {
		ctx.JSON(userErr.Code, gin.H{"message": userErr.Message})
		return
	}
	ctx.JSON(200, userData)
}

// Put updates the user by given ID and returns the user
func Put(ctx *gin.Context) {
	var uresource userResource
	var userJson UserModel.PublicUser

	if err := ctx.ShouldBindUri(&uresource); err != nil {
		ctx.JSON(403, gin.H{"message": "User ID is required."})
		return
	}
	if jsonErr := ctx.ShouldBind(&userJson); jsonErr != nil {
		ctx.JSON(403, gin.H{"message": "User data is invalid."})
		return
	}
	userData, err := UserDAO.Put(&userJson, uresource.ID)
	if err.Code != 0 {
		ctx.JSON(err.Code, gin.H{"message": err.Message})
		return
	}
	ctx.JSON(200, userData)
}

// UpdatePasswordAuthenticated patches the password for user given by ID
func UpdatePasswordAuthenticated(ctx *gin.Context) {
	var uresource userResource
	var passwordObject UserModel.PasswordReplacement

	if err := ctx.ShouldBindUri(&uresource); err != nil {
		ctx.JSON(403, gin.H{"message": "User ID is required."})
		return
	}
	if jsonErr := ctx.ShouldBind(&passwordObject); jsonErr != nil {
		ctx.JSON(403, gin.H{"message": "Password data is invalid."})
		return
	}
	userData, updateErr := UserDAO.UpdatePasswordAuthenticated(&passwordObject, uresource.ID)
	if updateErr.Code != 0 {
		ctx.JSON(updateErr.Code, gin.H{"message": updateErr.Message})
		return
	}
	ctx.JSON(200, userData)
}

// UpdatePasswordReset patches the password for user given by token
func UpdatePasswordReset(ctx *gin.Context) {
	var uresource forgotPasswordResource
	var passwordObject UserModel.PasswordReplacement

	if err := ctx.ShouldBindUri(&uresource); err != nil {
		ctx.JSON(403, gin.H{"message": err.Error()})
		return
	}
	if jsonErr := ctx.ShouldBind(&passwordObject); jsonErr != nil {
		ctx.JSON(403, gin.H{"message": "Password data is invalid."})
		return
	}
	userData, updateErr := UserDAO.UpdatePasswordReset(&passwordObject, uresource.ID, uresource.ResetToken)
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
	_, userErr := UserDAO.Delete(uresource.ID)
	if userErr.Code != 0 {
		ctx.JSON(userErr.Code, gin.H{"message": userErr.Message})
		return
	}
	ctx.JSON(200, gin.H{"success": true})
}

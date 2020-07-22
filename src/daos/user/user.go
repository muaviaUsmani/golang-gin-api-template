package user

import (
	"api/src/config"
	"api/src/helpers"
	UserModel "api/src/models/user"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/copier"
	"golang.org/x/crypto/bcrypt"
)

// Signup registers a new user
func Signup(signupData *UserModel.SignupData) (*UserModel.AuthenticatedUser, helpers.HTTPError) {
	var errorDetails helpers.HTTPError

	createdUser := new(UserModel.User)
	authenticatedUser := new(UserModel.AuthenticatedUser)
	copier.Copy(createdUser, &signupData)

	createdUser, err := Create(createdUser)
	if err.Code != 0 {
		return &UserModel.AuthenticatedUser{}, err
	}

	token, signErr := signToken(createdUser)
	if signErr != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: signErr}
		return &UserModel.AuthenticatedUser{}, errorDetails
	}

	createdUser.Token = token
	copier.Copy(authenticatedUser, &createdUser)
	return authenticatedUser, errorDetails
}

// Login authenticated a user given email and password
func Login(loginData *UserModel.LoginData) (*UserModel.AuthenticatedUser, helpers.HTTPError) {
	var errorDetails helpers.HTTPError

	userObj := new(UserModel.User)
	authenticatedUser := new(UserModel.AuthenticatedUser)

	err := config.Config.Db.Where("email=?", loginData.Email).First(&userObj).Error
	if err != nil {
		if userObj.ID == "" {
			errorDetails = helpers.HTTPError{Code: 401, Message: "Email or password is incorrect.", Error: errors.New("Email or password is incorrect.")}
			return &UserModel.AuthenticatedUser{}, errorDetails
		}
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return &UserModel.AuthenticatedUser{}, errorDetails
	}

	passwordErr := bcrypt.CompareHashAndPassword([]byte(userObj.Password), []byte(loginData.Password))
	if passwordErr != nil {
		errorDetails = helpers.HTTPError{Code: 401, Message: "Email or password is incorrect.", Error: errors.New("Email or password is incorrect.")}
		return &UserModel.AuthenticatedUser{}, errorDetails
	}

	token, signErr := signToken(userObj)
	if signErr != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: signErr}
		return &UserModel.AuthenticatedUser{}, errorDetails
	}

	userObj.Token = token
	copier.Copy(authenticatedUser, &userObj)
	return authenticatedUser, errorDetails
}

// Logout destroys user token for given ID
func Logout(id string) (bool, helpers.HTTPError) {
	var userObj UserModel.User
	var errorDetails helpers.HTTPError

	err := config.Config.Db.Where("id=?", id).First(&userObj).Error
	if err != nil {
		if userObj.ID == "" {
			errorDetails = helpers.HTTPError{Code: 404, Message: "Access token is invalid.", Error: errors.New("Access token is invalid.")}
			return false, errorDetails
		}
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return false, errorDetails
	}

	userObj.Token = ""
	config.Config.Db.Save(&userObj)
	return true, errorDetails
}

// Index gets the list of all users
func Index() (*[]UserModel.PublicUser, helpers.HTTPError) {
	var users []UserModel.User
	var publicUsers []UserModel.PublicUser
	var errorDetails helpers.HTTPError

	err := config.Config.Db.Find(&users).Error
	if err != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: err}
		return &publicUsers, errorDetails
	}
	copier.Copy(&publicUsers, &users)
	return &publicUsers, errorDetails
}

// Create adds a new user
func Create(userObj *UserModel.User) (*UserModel.User, helpers.HTTPError) {
	var errorDetails helpers.HTTPError

	if isEmailUnique(userObj.Email) {
		if userObj.Password == "" {
			errorDetails = helpers.HTTPError{Code: 401, Message: "Password is required.", Error: errors.New("Password is required..")}
			return &UserModel.User{}, errorDetails
		}

		userObj.ID = ""
		userObj.Token = ""
		userObj.ResetToken = ""
		userObj.CreatedAt = nil
		userObj.UpdatedAt = nil

		userObj.Password = UserModel.GeneratePassword(userObj.Password)

		err := config.Config.Db.Create(&userObj).Error
		if err != nil {
			errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: err}
			return &UserModel.User{}, errorDetails
		}

		return userObj, errorDetails
	}
	errorDetails = helpers.HTTPError{Code: 401, Message: "User already exists.", Error: errors.New("User already exists.")}
	return &UserModel.User{}, errorDetails
}

// Get fetches the user belonging to given ID
func Get(id string) (*UserModel.PublicUser, helpers.HTTPError) {
	var userObj UserModel.User
	var errorDetails helpers.HTTPError
	publicUser := new(UserModel.PublicUser)

	err := config.Config.Db.Where("id=?", id).First(&userObj).Error
	if err != nil {
		if userObj.ID == "" {
			errorDetails = helpers.HTTPError{Code: 404, Message: "User does not exist.", Error: errors.New("User does not exist.")}
			return &UserModel.PublicUser{}, errorDetails
		}
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return &UserModel.PublicUser{}, errorDetails
	}
	copier.Copy(publicUser, &userObj)

	return publicUser, errorDetails
}

// Put updates the entire user object belonging to given ID
func Put(userObj *UserModel.PublicUser, id string) (*UserModel.PublicUser, helpers.HTTPError) {
	storedUser := new(UserModel.User)
	var errorDetails helpers.HTTPError

	copier.Copy(storedUser, &userObj)

	fetchErr := config.Config.Db.First(&storedUser).Error
	if fetchErr != nil {
		errorDetails = helpers.HTTPError{Code: 404, Message: "User does not exist.", Error: errors.New("User does not exist.")}
		return &UserModel.PublicUser{}, errorDetails
	}

	copier.Copy(storedUser, &userObj)
	timeNow := time.Now()
	storedUser.UpdatedAt = &timeNow

	err := config.Config.Db.Save(&storedUser).Error
	if err != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return userObj, errorDetails
	}

	copier.Copy(&userObj, &storedUser)

	return userObj, errorDetails
}

// UpdatePasswordAuthenticated replaces the current password with given string
func UpdatePasswordAuthenticated(passwordObj *UserModel.PasswordReplacement, id string) (*UserModel.PublicUser, helpers.HTTPError) {
	publicUser := new(UserModel.PublicUser)
	var errorDetails helpers.HTTPError

	if isPasswordValid(passwordObj.ExistingPassword, id) == false {
		errorDetails = helpers.HTTPError{Code: 403, Message: "Existing password does not match.", Error: errors.New("Existing password does not match.")}
		return publicUser, errorDetails
	}

	return changePassword(passwordObj.NewPassword, id, false)
}

// UpdatePasswordReset replaces the current password if reset token is valid
func UpdatePasswordReset(passwordObj *UserModel.PasswordReplacement, id, token string) (*UserModel.PublicUser, helpers.HTTPError) {
	publicUser := new(UserModel.PublicUser)
	var errorDetails helpers.HTTPError

	if isTokenValid(token, id) == false {
		errorDetails = helpers.HTTPError{Code: 403, Message: "Reset token is invalid.", Error: errors.New("Reset token is invalid.")}
		return publicUser, errorDetails
	}

	return changePassword(passwordObj.NewPassword, id, true)
}

// Delete soft destroys user by given ID
func Delete(id string) (bool, helpers.HTTPError) {
	var errorDetails helpers.HTTPError
	userObj := new(UserModel.User)

	err := config.Config.Db.Where("id=?", id).First(&userObj).Error
	if err != nil {
		if userObj.ID == "" {
			errorDetails = helpers.HTTPError{Code: 404, Message: "User does not exist.", Error: errors.New("User does not exist.")}
			return false, errorDetails
		}
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return false, errorDetails
	}

	deleteErr := config.Config.Db.Delete(&userObj).Error
	if deleteErr != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return false, errorDetails
	}

	return true, errorDetails
}

func signToken(userObj *UserModel.User) (string, error) {
	claims := UserModel.CustomAccessToken{
		userObj.ID,
		userObj.Email,
		time.Now(),
		jwt.StandardClaims{
			ExpiresAt: time.Now().AddDate(0, 1, 0).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString([]byte(config.Config.AppKey))
	userObj.Token = tokenString
	config.Config.Db.Save(&userObj)
	return tokenString, err
}

func changePassword(password, id string, nullifyToken bool) (*UserModel.PublicUser, helpers.HTTPError) {
	var userObj UserModel.User
	publicUser := new(UserModel.PublicUser)
	var errorDetails helpers.HTTPError

	fetchErr := config.Config.Db.Where("id=?", id).First(&userObj).Error
	if fetchErr != nil {
		errorDetails = helpers.HTTPError{Code: 404, Message: "User does not exist.", Error: fetchErr}
		return &UserModel.PublicUser{}, errorDetails
	}

	userObj.Password = UserModel.GeneratePassword(password)
	userObj.UpdatedAt = nil
	if nullifyToken {
		userObj.ResetToken = ""
	}
	saveErr := config.Config.Db.Save(&userObj).Error
	if saveErr != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: saveErr}
		return publicUser, errorDetails
	}

	copier.Copy(publicUser, &userObj)
	return publicUser, errorDetails
}

func isEmailUnique(email string) bool {
	var userObj UserModel.User

	_ = config.Config.Db.Where("email=?", email).First(&userObj).Error
	if userObj.ID != "" {
		return false
	}
	return true
}

func isPasswordValid(password, id string) bool {
	var userObj UserModel.User

	_ = config.Config.Db.Where("id=?", id).First(&userObj).Error
	if userObj.ID == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(userObj.Password), []byte(password))
	if err != nil {
		return false
	}
	return true
}

func isTokenValid(token, id string) bool {
	var userObj UserModel.User

	_ = config.Config.Db.Where("id=? AND reset_token=?", id, token).First(&userObj).Error
	if userObj.ID == "" {
		return false
	}
	return true
}

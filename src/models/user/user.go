package user

import (
	"api/src/config"
	"api/src/helpers"
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/copier"
	"golang.org/x/crypto/bcrypt"
)

// PublicUser data type
type PublicUser struct {
	ID        string     `form:"id" json:"id"`
	FirstName string     `form:"firstName" json:"firstName"`
	LastName  string     `form:"lastName" json:"lastName"`
	Email     string     `form:"email" json:"email"`
	AvatarURL string     `form:"avatarUrl" json:"avatarUrl"`
	CreatedAt *time.Time `form:"createdAt" json:"createdAt"`
	UpdatedAt *time.Time `form:"updatedAt" json:"updatedAt"`
}

// AuthenticatedUser data type
type AuthenticatedUser struct {
	PublicUser
	Token string `form:"token" json:"token"`
}

// User data type
type User struct {
	AuthenticatedUser
	ResetToken string     `form:"resetToken"`
	Password   string     `form:"password"`
	DeletedAt  *time.Time `form:"deletedAt"`
}

// PasswordReplacement data type
type PasswordReplacement struct {
	ExistingPassword string `json:"existingPassword"`
	NewPassword      string `json:"newPassword"`
}

// CustomAccessToken data type
type CustomAccessToken struct {
	ID      string    `json:"id"`
	Email   string    `json:"email"`
	LoginAt time.Time `json:"login_at"`
	jwt.StandardClaims
}

// SignupData data type
type SignupData struct {
	FirstName string `form:"firstName" json:"firstName" binding:"required"`
	LastName  string `form:"lastName" json:"lastName" binding:"required"`
	Email     string `form:"email" json:"email" binding:"required"`
	Password  string `form:"password" json:"password" binding:"required"`
}

// LoginData data type
type LoginData struct {
	Email    string `form:"email" json:"email" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

// Signup registers a new user
func Signup(signupData *SignupData) (*AuthenticatedUser, helpers.HTTPError) {
	var errorDetails helpers.HTTPError

	user := new(User)
	authenticatedUser := new(AuthenticatedUser)
	copier.Copy(user, &signupData)

	createdUser, err := Create(user)
	if err.Code != 0 {
		return &AuthenticatedUser{}, err
	}

	token, signErr := signToken(createdUser)
	if signErr != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: signErr}
		return &AuthenticatedUser{}, errorDetails
	}

	createdUser.Token = token
	copier.Copy(authenticatedUser, &createdUser)
	return authenticatedUser, errorDetails
}

// Login authenticated a user given email and password
func Login(loginData *LoginData) (*AuthenticatedUser, helpers.HTTPError) {
	var errorDetails helpers.HTTPError

	user := new(User)
	authenticatedUser := new(AuthenticatedUser)

	err := config.Config.Db.Where("email=?", loginData.Email).First(&user).Error
	if err != nil {
		if user.ID == "" {
			errorDetails = helpers.HTTPError{Code: 401, Message: "Email or password is incorrect.", Error: errors.New("Email or password is incorrect.")}
			return &AuthenticatedUser{}, errorDetails
		}
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return &AuthenticatedUser{}, errorDetails
	}

	passwordErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password))
	if passwordErr != nil {
		errorDetails = helpers.HTTPError{Code: 401, Message: "Email or password is incorrect.", Error: errors.New("Email or password is incorrect.")}
		return &AuthenticatedUser{}, errorDetails
	}

	token, signErr := signToken(user)
	if signErr != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: signErr}
		return &AuthenticatedUser{}, errorDetails
	}

	user.Token = token
	copier.Copy(authenticatedUser, &user)
	return authenticatedUser, errorDetails
}

// Logout destroys user token for given ID
func Logout(id string) (bool, helpers.HTTPError) {
	var user User
	var errorDetails helpers.HTTPError

	err := config.Config.Db.Where("id=?", id).First(&user).Error
	if err != nil {
		if user.ID == "" {
			errorDetails = helpers.HTTPError{Code: 404, Message: "Access token is invalid.", Error: errors.New("Access token is invalid.")}
			return false, errorDetails
		}
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return false, errorDetails
	}

	user.Token = ""
	config.Config.Db.Save(&user)
	return true, errorDetails
}

// Index gets the list of all users
func Index() (*[]PublicUser, helpers.HTTPError) {
	var users []User
	var publicUsers []PublicUser
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
func Create(user *User) (*User, helpers.HTTPError) {
	var errorDetails helpers.HTTPError

	if isEmailUnique(user.Email) {
		if user.Password == "" {
			errorDetails = helpers.HTTPError{Code: 401, Message: "Password is required.", Error: errors.New("Password is required..")}
			return &User{}, errorDetails
		}

		user.ID = ""
		user.Token = ""
		user.ResetToken = ""
		user.CreatedAt = nil
		user.UpdatedAt = nil

		user.Password = generatePassword(user.Password)

		err := config.Config.Db.Create(&user).Error
		if err != nil {
			errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: err}
			return &User{}, errorDetails
		}

		return user, errorDetails
	}
	errorDetails = helpers.HTTPError{Code: 401, Message: "User already exists.", Error: errors.New("User already exists.")}
	return &User{}, errorDetails
}

// Get fetches the user belonging to given ID
func Get(id string) (*PublicUser, helpers.HTTPError) {
	var user User
	var errorDetails helpers.HTTPError
	publicUser := new(PublicUser)

	err := config.Config.Db.Where("id=?", id).First(&user).Error
	if err != nil {
		if user.ID == "" {
			errorDetails = helpers.HTTPError{Code: 404, Message: "User does not exist.", Error: errors.New("User does not exist.")}
			return &PublicUser{}, errorDetails
		}
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return &PublicUser{}, errorDetails
	}
	copier.Copy(publicUser, &user)

	return publicUser, errorDetails
}

// Put updates the entire user object belonging to given ID
func Put(user *PublicUser, id string) (*PublicUser, helpers.HTTPError) {
	storedUser := new(User)
	var errorDetails helpers.HTTPError

	copier.Copy(storedUser, &user)

	fetchErr := config.Config.Db.First(&storedUser).Error
	if fetchErr != nil {
		errorDetails = helpers.HTTPError{Code: 404, Message: "User does not exist.", Error: errors.New("User does not exist.")}
		return &PublicUser{}, errorDetails
	}

	copier.Copy(storedUser, &user)
	timeNow := time.Now()
	storedUser.UpdatedAt = &timeNow

	err := config.Config.Db.Save(&storedUser).Error
	if err != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return user, errorDetails
	}

	copier.Copy(&user, &storedUser)

	return user, errorDetails
}

// UpdatePasswordAuthenticated replaces the current password with given string
func UpdatePasswordAuthenticated(passwordObj *PasswordReplacement, id string) (*PublicUser, helpers.HTTPError) {
	publicUser := new(PublicUser)
	var errorDetails helpers.HTTPError

	if isPasswordValid(passwordObj.ExistingPassword, id) == false {
		errorDetails = helpers.HTTPError{Code: 403, Message: "Existing password does not match.", Error: errors.New("Existing password does not match.")}
		return publicUser, errorDetails
	}

	return changePassword(passwordObj.NewPassword, id, false)
}

// UpdatePasswordReset replaces the current password if reset token is valid
func UpdatePasswordReset(passwordObj *PasswordReplacement, id, token string) (*PublicUser, helpers.HTTPError) {
	publicUser := new(PublicUser)
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
	user := new(User)

	err := config.Config.Db.Where("id=?", id).First(&user).Error
	if err != nil {
		if user.ID == "" {
			errorDetails = helpers.HTTPError{Code: 404, Message: "User does not exist.", Error: errors.New("User does not exist.")}
			return false, errorDetails
		}
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return false, errorDetails
	}

	deleteErr := config.Config.Db.Delete(&user).Error
	if deleteErr != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: errors.New("Something went wrong.")}
		return false, errorDetails
	}

	return true, errorDetails
}

func signToken(user *User) (string, error) {
	claims := CustomAccessToken{
		user.ID,
		user.Email,
		time.Now(),
		jwt.StandardClaims{
			ExpiresAt: time.Now().AddDate(0, 1, 0).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString([]byte(config.Config.AppKey))
	user.Token = tokenString
	config.Config.Db.Save(&user)
	return tokenString, err
}

func changePassword(password, id string, nullifyToken bool) (*PublicUser, helpers.HTTPError) {
	var user User
	publicUser := new(PublicUser)
	var errorDetails helpers.HTTPError

	fetchErr := config.Config.Db.Where("id=?", id).First(&user).Error
	if fetchErr != nil {
		errorDetails = helpers.HTTPError{Code: 404, Message: "User does not exist.", Error: fetchErr}
		return &PublicUser{}, errorDetails
	}

	user.Password = generatePassword(password)
	user.UpdatedAt = nil
	if nullifyToken {
		user.ResetToken = ""
	}
	saveErr := config.Config.Db.Save(&user).Error
	if saveErr != nil {
		errorDetails = helpers.HTTPError{Code: 500, Message: "Something went wrong.", Error: saveErr}
		return publicUser, errorDetails
	}

	copier.Copy(publicUser, &user)
	return publicUser, errorDetails
}

func isEmailUnique(email string) bool {
	var user User

	_ = config.Config.Db.Where("email=?", email).First(&user).Error
	if user.ID != "" {
		return false
	}
	return true
}

func isPasswordValid(password, id string) bool {
	var user User

	_ = config.Config.Db.Where("id=?", id).First(&user).Error
	if user.ID == "" {
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		return false
	}
	return true
}

func isTokenValid(token, id string) bool {
	var user User

	_ = config.Config.Db.Where("id=? AND reset_token=?", id, token).First(&user).Error
	if user.ID == "" {
		return false
	}
	return true
}

func generatePassword(password string) string {
	passwordBs, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(passwordBs)
}

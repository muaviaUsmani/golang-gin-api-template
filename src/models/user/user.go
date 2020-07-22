package user

import (
	"time"

	"github.com/dgrijalva/jwt-go"
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

func GeneratePassword(password string) string {
	passwordBs, _ := bcrypt.GenerateFromPassword([]byte(password), 10)
	return string(passwordBs)
}

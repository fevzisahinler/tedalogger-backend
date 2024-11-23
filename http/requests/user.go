package requests

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/go-playground/validator/v10"

	"tedalogger-backend/models"
)

type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
	FullName    string `json:"fullName" validate:"required"`
	Email       string `json:"email" validate:"required,email"`
	PhoneNumber string `json:"phoneNumber" validate:"required"`
}

func (u *CreateUserRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(u)
}

func HashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

func (u *CreateUserRequest) ToModel() *models.User {
	return &models.User{
		Username:    u.Username,
		Password:    HashPassword(u.Password),
		FullName:    u.FullName,
		Email:       u.Email,
		PhoneNumber: u.PhoneNumber,
	}
}

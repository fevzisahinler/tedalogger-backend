package requests

import (
	"github.com/go-playground/validator/v10"
)

type CreateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=100"`
	Password    string `json:"password" validate:"required,min=8"`
	Name        string `json:"name" validate:"required,max=20"`
	Surname     string `json:"surname" validate:"required,max=20"`
	Email       string `json:"email" validate:"required,email"`
	PhoneNumber string `json:"phoneNumber" validate:"required"`
}

func (u *CreateUserRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(u)
}

type UpdateUserRequest struct {
	Username    string `json:"username" validate:"required,min=3,max=100"`
	Password    string `json:"password,omitempty" validate:"omitempty,min=8"`
	Name        string `json:"name" validate:"required,max=20"`
	Surname     string `json:"surname" validate:"required,max=20"`
	Email       string `json:"email" validate:"required,email"`
	PhoneNumber string `json:"phoneNumber" validate:"required"`
}

func (u *UpdateUserRequest) Validate() error {
	validate := validator.New()
	return validate.Struct(u)
}

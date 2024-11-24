package controllers

import (
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"

	"tedalogger-backend/config"
	"tedalogger-backend/db"
	"tedalogger-backend/http/responses"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
	"tedalogger-backend/utils"
)

func Login(c *fiber.Ctx) error {
	type LoginRequest struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	loginReq := new(LoginRequest)
	if err := c.BodyParser(loginReq); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse login request")
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	var user models.User
	if err := db.DB.Where("username = ?", loginReq.Username).First(&user).Error; err != nil {
		logger.Logger.WithError(err).Error("User not found")
		return c.Status(fiber.StatusUnauthorized).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid credentials",
		})
	}

	if err := utils.CheckPasswordHash(loginReq.Password, user.Password); err != nil {
		logger.Logger.Error("Invalid password")
		return c.Status(fiber.StatusUnauthorized).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid credentials",
		})
	}

	cfg, _ := config.LoadConfig()
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["id"] = user.ID
	claims["username"] = user.Username
	claims["exp"] = time.Now().Add(time.Hour * 2).Unix()

	tokenString, err := token.SignedString([]byte(cfg.JwtSecretKey))
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to generate token")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not login",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Login successful",
		Data:    fiber.Map{"token": tokenString},
	})
}

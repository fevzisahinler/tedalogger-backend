package controllers

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"

	"tedalogger-backend/config"
	"tedalogger-backend/db"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
)

func Login(c *fiber.Ctx) error {
	type LoginRequest struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	loginReq := new(LoginRequest)
	if err := c.BodyParser(loginReq); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse login request")
		return fiber.NewError(fiber.StatusBadRequest, "Invalid input")
	}

	var user models.User
	if err := db.DB.Where("username = ?", loginReq.Username).First(&user).Error; err != nil {
		logger.Logger.WithError(err).Error("User not found")
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
	}

	if user.Password != HashPassword(loginReq.Password) {
		logger.Logger.Error("Invalid password")
		return fiber.NewError(fiber.StatusUnauthorized, "Invalid credentials")
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
		return fiber.NewError(fiber.StatusInternalServerError, "Could not login")
	}

	return c.JSON(fiber.Map{
		"token": tokenString,
	})
}

func HashPassword(password string) string {
	hash := sha256.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

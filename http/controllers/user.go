package controllers

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
)

func Register(c *fiber.Ctx) error {
	requestUser := new(requests.CreateUserRequest)
	if err := c.BodyParser(requestUser); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid input",
		})
	}

	if err := requestUser.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid input",
		})
	}

	var existingUser models.User
	if err := db.DB.Where("username = ? OR email = ?", requestUser.Username, requestUser.Email).First(&existingUser).Error; err != nil && err != gorm.ErrRecordNotFound {
		logger.Logger.WithError(err).Error("Failed to check existing user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "An unexpected error occurred",
		})
	}

	if existingUser.ID != 0 {
		logger.Logger.Warn("User already exists")
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "User already exists",
		})
	}

	userModel := requestUser.ToModel()
	if err := db.DB.Create(&userModel).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to create user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "An unexpected error occurred",
		})
	}

	logger.Logger.WithFields(map[string]interface{}{
		"username": userModel.Username,
	}).Info("User created successfully")

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User created successfully",
	})
}

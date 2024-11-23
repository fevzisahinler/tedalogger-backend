package controllers

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/logger"
)

func Register(c *fiber.Ctx) error {
	requestUser := new(requests.CreateUserRequest)
	if err := c.BodyParser(requestUser); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse request body")
		return fiber.NewError(fiber.StatusBadRequest, "Invalid input")
	}

	if err := requestUser.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed")
		return fiber.NewError(fiber.StatusBadRequest, "Validation failed: "+err.Error())
	}

	userModel := requestUser.ToModel()

	if result := db.DB.Create(&userModel); result.Error != nil {
		logger.Logger.WithError(result.Error).Error("Failed to create user")
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to create user")
	}

	logger.Logger.WithFields(map[string]interface{}{
		"username": userModel.Username,
		"user_id":  userModel.ID,
	}).Info("User created successfully")

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User created successfully",
		"user":    userModel,
	})
}

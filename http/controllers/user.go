package controllers

import (
	"errors"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/http/responses"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
	"tedalogger-backend/utils"
)

func Register(c *fiber.Ctx) error {
	requestUser := new(requests.CreateUserRequest)
	if err := c.BodyParser(requestUser); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := requestUser.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	var existingUser models.User
	if err := db.DB.Where("username = ? OR email = ?", requestUser.Username, requestUser.Email).First(&existingUser).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		logger.Logger.WithError(err).Error("Failed to check existing user")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	if existingUser.ID != 0 {
		logger.Logger.Warn("User already exists")
		return c.Status(fiber.StatusConflict).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User already exists",
		})
	}

	hashedPassword, err := utils.HashPassword(requestUser.Password)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to hash password")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	userModel := &models.User{
		Username:    requestUser.Username,
		Password:    hashedPassword,
		Name:        requestUser.Name,
		Surname:     requestUser.Surname,
		Email:       requestUser.Email,
		PhoneNumber: requestUser.PhoneNumber,
	}

	if err := db.DB.Create(&userModel).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to create user")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	logger.Logger.WithFields(map[string]interface{}{
		"username": userModel.Username,
	}).Info("User created successfully")

	return c.Status(fiber.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User created successfully",
		Data:    userModel,
	})
}

func EditUser(c *fiber.Ctx) error {
	id := c.Params("id")
	userID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid user ID",
		})
	}

	var updateUserRequest requests.UpdateUserRequest
	if err := c.BodyParser(&updateUserRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unable to parse JSON",
		})
	}

	if err := updateUserRequest.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: err.Error(),
		})
	}

	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User not found",
		})
	}

	user.Username = updateUserRequest.Username
	if updateUserRequest.Password != "" {
		hashedPassword, err := utils.HashPassword(updateUserRequest.Password)
		if err != nil {
			logger.Logger.WithError(err).Error("Failed to hash password")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "An unexpected error occurred",
			})
		}
		user.Password = hashedPassword
	}
	user.Name = updateUserRequest.Name
	user.Surname = updateUserRequest.Surname
	user.Email = updateUserRequest.Email
	user.PhoneNumber = updateUserRequest.PhoneNumber

	if err := db.DB.Save(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User could not be updated",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User updated successfully",
		Data:    user,
	})
}

func DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	userID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid user ID",
		})
	}

	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User not found",
		})
	}

	if err := db.DB.Delete(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User could not be deleted",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User deleted successfully",
	})
}

func GetAllUser(c *fiber.Ctx) error {
	var users []models.User
	if err := db.DB.Find(&users).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to fetch users")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch users",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Users fetched successfully",
		Data:    users,
	})
}

func GetUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var user models.User
	if err := db.DB.First(&user, id).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User not found",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User fetched successfully",
		Data:    user,
	})
}

func GetCurrentUser(c *fiber.Ctx) error {
	claims, ok := c.Locals("user").(jwt.MapClaims)
	if !ok {
		logger.Logger.Error("Failed to cast user claims to jwt.MapClaims")
		return c.Status(fiber.StatusUnauthorized).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unauthorized: Invalid token claims",
		})
	}

	idFloat, ok := claims["id"].(float64)
	if !ok {
		logger.Logger.Error("Invalid token claims: 'id' field is missing or invalid")
		return c.Status(fiber.StatusUnauthorized).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid token claims structure",
		})
	}

	userID := uint(idFloat)
	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		logger.Logger.WithError(err).Error("User not found")
		return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User not found",
		})
	}

	logger.Logger.WithField("user", user).Info("User fetched successfully")
	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User fetched successfully",
		Data:    user,
	})
}

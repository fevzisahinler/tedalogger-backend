package controllers

import (
	"errors"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"strconv"
	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/http/responses"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
)

func CreateSignSettings(c *fiber.Ctx) error {
	var req requests.CreateSignSettingsRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	signSettings := models.SignSettings{
		FileSigningMethod: req.FileSigningMethod,
		FileSizeLimitMB:   req.FileSizeLimitMB,
		BackupFrequency:   req.BackupFrequency,
	}

	if err := db.DB.Create(&signSettings).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to create sign settings")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to create sign settings",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Sign settings created successfully",
		Data:    signSettings,
	})
}

func GetAllSignSettings(c *fiber.Ctx) error {
	var settings []models.SignSettings
	if err := db.DB.Find(&settings).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to fetch sign settings")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch sign settings",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Sign settings fetched successfully",
		Data:    settings,
	})
}

func GetSignSettings(c *fiber.Ctx) error {
	id := c.Params("id")
	settingID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid sign settings ID",
		})
	}

	var setting models.SignSettings
	if err := db.DB.First(&setting, settingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Sign settings not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to fetch sign settings")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch sign settings",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Sign settings fetched successfully",
		Data:    setting,
	})
}

func UpdateSignSettings(c *fiber.Ctx) error {
	id := c.Params("id")
	settingID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid sign settings ID",
		})
	}

	var req requests.UpdateSignSettingsRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	var setting models.SignSettings
	if err := db.DB.First(&setting, settingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Sign settings not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to fetch sign settings")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch sign settings",
		})
	}

	setting.FileSigningMethod = req.FileSigningMethod
	setting.FileSizeLimitMB = req.FileSizeLimitMB
	setting.BackupFrequency = req.BackupFrequency

	if err := db.DB.Save(&setting).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to update sign settings")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to update sign settings",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Sign settings updated successfully",
		Data:    setting,
	})
}

func DeleteSignSettings(c *fiber.Ctx) error {
	id := c.Params("id")
	settingID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid sign settings ID",
		})
	}

	var setting models.SignSettings
	if err := db.DB.First(&setting, settingID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Sign settings not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to fetch sign settings")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch sign settings",
		})
	}

	if err := db.DB.Delete(&setting).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to delete sign settings")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to delete sign settings",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Sign settings deleted successfully",
	})
}

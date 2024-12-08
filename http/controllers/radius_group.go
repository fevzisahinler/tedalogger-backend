package controllers

import (
	"errors"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"net/http"
	"strconv"
	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/http/responses"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
)

func CreateRadiusGroup(c *fiber.Ctx) error {
	var req requests.CreateOrUpdateRadiusGroupRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Radius Group create request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for Radius Group create request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	radgroup := models.RadGroup{
		RadiusGroupName:       req.RadiusGroupName,
		SessionTimeout:        req.SessionTimeout,
		IdleTimeout:           req.IdleTimeout,
		SimultaneousUse:       req.SimultaneousUse,
		Bandwidth:             req.Bandwidth,
		TimeOfDayRestrictions: req.TimeOfDayRestrictions,
		Description:           req.Description,
	}

	if err := db.DB.Create(&radgroup).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to insert NAS into PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not create NAS",
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "NAS created successfully",
		Data:    radgroup,
	})
}

func UpdateRadiusGroup(c *fiber.Ctx) error {
	id := c.Params("id")
	RadGroupID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid Radius Group ID",
		})
	}

	var req requests.CreateOrUpdateRadiusGroupRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Radius Group update request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for Radius update request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	var radiusGroup models.RadGroup
	if err := db.DB.First(&radiusGroup, RadGroupID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Radius Group not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	//oldRadiusGroupName := radiusGroup.RadiusGroupName

	radiusGroup.RadiusGroupName = req.RadiusGroupName
	radiusGroup.SessionTimeout = req.SessionTimeout
	radiusGroup.IdleTimeout = req.SessionTimeout
	radiusGroup.SimultaneousUse = req.SimultaneousUse
	radiusGroup.Bandwidth = req.Bandwidth
	radiusGroup.TimeOfDayRestrictions = req.TimeOfDayRestrictions
	radiusGroup.Description = req.Description

	if err := db.DB.Save(&radiusGroup).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to update NAS in PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not update Radius Group",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "NAS updated successfully",
		Data:    radiusGroup,
	})
}

func GetAllRadiusGroup(c *fiber.Ctx) error {
	var RadiusGroupList []models.RadGroup
	if err := db.DB.Find(&RadiusGroupList).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to fetch Radius Group list from PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not retrieve Radius Group list",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Radius Group list retrieved successfully",
		Data:    RadiusGroupList,
	})
}

func DeleteRadiusGroup(c *fiber.Ctx) error {
	id := c.Params("id")
	RadGroupID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid Radius Group ID",
		})
	}

	var radiusGroup models.RadGroup
	if err := db.DB.First(&radiusGroup, RadGroupID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Radius Group not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	if err := db.DB.Delete(&radiusGroup).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to delete Radius Group from PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not delete Radius Group",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Radius Group deleted successfully",
	})

}

// http/controllers/portal.go

package controllers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/http/responses"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func CreatePortal(c *fiber.Ctx) error {
	var req requests.CreateOrUpdatePortalRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Portal create request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for Portal create request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	loginComponentsJSON, err := json.Marshal(req.LoginComponents)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to marshal loginComponents")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to process components",
		})
	}

	signupComponentsJSON, err := json.Marshal(req.SignupComponents)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to marshal signupComponents")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to process components",
		})
	}

	themeJSON, err := json.Marshal(req.Theme)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to marshal theme")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to process theme",
		})
	}

	portal := models.Portal{
		PortalID:         req.PortalID,
		Name:             req.Name,
		RadiusGroupName:  req.RadiusGroupName,
		NasName:          req.NasName,
		LoginComponents:  loginComponentsJSON,
		SignupComponents: signupComponentsJSON,
		Theme:            themeJSON,
		Logo:             req.Logo,
		Background:       req.Background,
		OtpEnabled:       req.OtpEnabled,
	}

	if err := db.DB.Create(&portal).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to create Portal in PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not create portal",
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Portal created successfully",
		Data:    portal,
	})
}

// UpdatePortal
func UpdatePortal(c *fiber.Ctx) error {
	id := c.Params("id")
	portalID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid Portal ID",
		})
	}

	var req requests.CreateOrUpdatePortalRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Portal update request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for Portal update request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	var portal models.Portal
	if err := db.DB.First(&portal, portalID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Portal not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	loginComponentsJSON, err := json.Marshal(req.LoginComponents)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to marshal loginComponents on update")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to process components",
		})
	}

	signupComponentsJSON, err := json.Marshal(req.SignupComponents)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to marshal signupComponents on update")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to process components",
		})
	}

	themeJSON, err := json.Marshal(req.Theme)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to marshal theme on update")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to process theme",
		})
	}

	portal.PortalID = req.PortalID
	portal.Name = req.Name
	portal.RadiusGroupName = req.RadiusGroupName
	portal.NasName = req.NasName
	portal.LoginComponents = loginComponentsJSON
	portal.SignupComponents = signupComponentsJSON
	portal.Theme = themeJSON
	portal.Logo = req.Logo
	portal.Background = req.Background
	portal.OtpEnabled = req.OtpEnabled // Yeni alan güncellendi

	if err := db.DB.Save(&portal).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to update Portal in PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not update portal",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Portal updated successfully",
		Data:    portal,
	})
}

// DeletePortal
func DeletePortal(c *fiber.Ctx) error {
	id := c.Params("id")
	portalID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid Portal ID",
		})
	}

	var portal models.Portal
	if err := db.DB.First(&portal, portalID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Portal not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	if err := db.DB.Delete(&portal).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to delete Portal from PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not delete portal",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Portal deleted successfully",
	})
}

// GetAllPortals
func GetAllPortals(c *fiber.Ctx) error {
	var portals []models.Portal
	if err := db.DB.Find(&portals).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to fetch Portal list from PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not retrieve portal list",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Portal list retrieved successfully",
		Data:    portals,
	})
}

// GetPortalByID
func GetPortalByID(c *fiber.Ctx) error {
	id := c.Params("id")
	portalID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid Portal ID",
		})
	}

	var portal models.Portal
	if err := db.DB.First(&portal, portalID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Portal not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Portal retrieved successfully",
		Data:    portal,
	})
}

// GetPortalByUUID
func GetPortalByUUID(c *fiber.Ctx) error {
	uuid := c.Params("uuid")

	var portal models.Portal
	if err := db.DB.Where("portal_id = ?", uuid).First(&portal).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Portal not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Portal retrieved successfully",
		Data:    portal,
	})
}

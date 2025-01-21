package controllers

import (
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

func CreateNAS(c *fiber.Ctx) error {
	var req requests.CreateOrUpdateNASRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse NAS create request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for NAS create request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	nas := models.NAS{
		Nasname:           req.Nasname,
		Shortname:         req.Shortname,
		Type:              req.Type,
		Brand:             req.Brand,
		Port:              req.Port,
		Secret:            req.Secret,
		Server:            req.Server,
		Community:         req.Community,
		Description:       req.Description,
		SNMPEnabled:       req.SNMPEnabled,
		Syslog5651Enabled: req.Syslog5651Enabled,
	}

	if err := db.DB.Create(&nas).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to insert NAS into PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not create NAS",
		})
	}

	if err := db.RadiusDB.Exec(
		`INSERT INTO nas (nasname, shortname, type, ports, secret, server, community, description)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		nas.Nasname, nas.Shortname, nas.Type, nas.Port, nas.Secret, nas.Server, nas.Community, nas.Description,
	).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to insert NAS into Radius DB")
		db.DB.Delete(&nas)
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not create NAS in radius",
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "NAS created successfully",
		Data:    nas,
	})
}

func UpdateNAS(c *fiber.Ctx) error {
	id := c.Params("id")
	nasID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid NAS ID",
		})
	}

	var req requests.CreateOrUpdateNASRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse NAS update request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for NAS update request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	var nas models.NAS
	if err := db.DB.First(&nas, nasID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "NAS not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	oldNasName := nas.Nasname

	nas.Nasname = req.Nasname
	nas.Shortname = req.Shortname
	nas.Type = req.Type
	nas.Brand = req.Brand
	nas.Port = req.Port
	nas.Secret = req.Secret
	nas.Server = req.Server
	nas.Community = req.Community
	nas.Description = req.Description
	nas.SNMPEnabled = req.SNMPEnabled
	nas.Syslog5651Enabled = req.Syslog5651Enabled

	if err := db.DB.Save(&nas).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to update NAS in PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not update NAS",
		})
	}

	if err := db.RadiusDB.Exec(
		`UPDATE nas SET nasname=?, shortname=?, type=?, ports=?, secret=?, server=?, community=?, description=? 
		 WHERE nasname=?`,
		nas.Nasname, nas.Shortname, nas.Type, nas.Port, nas.Secret, nas.Server, nas.Community, nas.Description, oldNasName,
	).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to update NAS in Radius DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not update NAS in radius",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "NAS updated successfully",
		Data:    nas,
	})
}

func DeleteNAS(c *fiber.Ctx) error {
	id := c.Params("id")
	nasID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid NAS ID",
		})
	}

	var nas models.NAS
	if err := db.DB.First(&nas, nasID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "NAS not found",
			})
		}
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "An unexpected error occurred",
		})
	}

	if err := db.DB.Delete(&nas).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to delete NAS from PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not delete NAS",
		})
	}

	if err := db.RadiusDB.Exec(`DELETE FROM nas WHERE nasname=?`, nas.Nasname).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to delete NAS from Radius DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not delete NAS in radius",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "NAS deleted successfully",
	})
}

func GetAllNAS(c *fiber.Ctx) error {
	var nasList []models.NAS
	if err := db.DB.Find(&nasList).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to fetch NAS list from PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not retrieve NAS list",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "NAS list retrieved successfully",
		Data:    nasList,
	})
}

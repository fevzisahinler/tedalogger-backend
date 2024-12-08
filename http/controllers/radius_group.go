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

	// Begin transaction on PostgreSQL
	tx := db.DB.Begin()
	if err := tx.Create(&radgroup).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to insert Radius Group into PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not create Radius Group",
		})
	}

	if err := db.RadiusDB.Exec("INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES (?, 'Simultaneous-Use', ':=', ?)",
		radgroup.RadiusGroupName, radgroup.SimultaneousUse).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to insert Simultaneous-Use into Radius radgroupcheck")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not create Radius Group in radius (radgroupcheck)",
		})
	}

	if radgroup.TimeOfDayRestrictions != "" {
		if err := db.RadiusDB.Exec("INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES (?, 'Login-Time', ':=', ?)",
			radgroup.RadiusGroupName, radgroup.TimeOfDayRestrictions).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to insert Login-Time into Radius radgroupcheck")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Could not create Radius Group in radius (radgroupcheck)",
			})
		}
	}

	if radgroup.SessionTimeout > 0 {
		if err := db.RadiusDB.Exec("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (?, 'Session-Timeout', ':=', ?)",
			radgroup.RadiusGroupName, radgroup.SessionTimeout).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to insert Session-Timeout into Radius radgroupreply")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Could not create Radius Group in radius (radgroupreply)",
			})
		}
	}

	if radgroup.IdleTimeout > 0 {
		if err := db.RadiusDB.Exec("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (?, 'Idle-Timeout', ':=', ?)",
			radgroup.RadiusGroupName, radgroup.IdleTimeout).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to insert Idle-Timeout into Radius radgroupreply")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Could not create Radius Group in radius (radgroupreply)",
			})
		}
	}

	if radgroup.Bandwidth != "" {
		if err := db.RadiusDB.Exec("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (?, 'Mikrotik-Rate-Limit', ':=', ?)",
			radgroup.RadiusGroupName, radgroup.Bandwidth).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to insert Bandwidth into Radius radgroupreply")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Could not create Radius Group in radius (radgroupreply)",
			})
		}
	}

	tx.Commit()

	return c.Status(http.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Radius Group created successfully",
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

	oldRadiusGroupName := radiusGroup.RadiusGroupName

	radiusGroup.RadiusGroupName = req.RadiusGroupName
	radiusGroup.SessionTimeout = req.SessionTimeout
	radiusGroup.IdleTimeout = req.IdleTimeout
	radiusGroup.SimultaneousUse = req.SimultaneousUse
	radiusGroup.Bandwidth = req.Bandwidth
	radiusGroup.TimeOfDayRestrictions = req.TimeOfDayRestrictions
	radiusGroup.Description = req.Description

	tx := db.DB.Begin()
	if err := tx.Save(&radiusGroup).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to update Radius Group in PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not update Radius Group",
		})
	}

	if err := db.RadiusDB.Exec("DELETE FROM radgroupcheck WHERE groupname=?", oldRadiusGroupName).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to delete old radgroupcheck entries in Radius DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not update Radius Group in radius",
		})
	}

	if err := db.RadiusDB.Exec("DELETE FROM radgroupreply WHERE groupname=?", oldRadiusGroupName).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to delete old radgroupreply entries in Radius DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not update Radius Group in radius",
		})
	}

	if err := db.RadiusDB.Exec("INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES (?, 'Simultaneous-Use', ':=', ?)",
		radiusGroup.RadiusGroupName, radiusGroup.SimultaneousUse).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to insert Simultaneous-Use into Radius radgroupcheck on update")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not update Radius Group in radius (radgroupcheck)",
		})
	}

	if radiusGroup.TimeOfDayRestrictions != "" {
		if err := db.RadiusDB.Exec("INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES (?, 'Login-Time', ':=', ?)",
			radiusGroup.RadiusGroupName, radiusGroup.TimeOfDayRestrictions).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to insert Login-Time into Radius radgroupcheck on update")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Could not update Radius Group in radius (radgroupcheck)",
			})
		}
	}

	if radiusGroup.SessionTimeout > 0 {
		if err := db.RadiusDB.Exec("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (?, 'Session-Timeout', ':=', ?)",
			radiusGroup.RadiusGroupName, radiusGroup.SessionTimeout).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to insert Session-Timeout into Radius radgroupreply on update")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Could not update Radius Group in radius (radgroupreply)",
			})
		}
	}

	if radiusGroup.IdleTimeout > 0 {
		if err := db.RadiusDB.Exec("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (?, 'Idle-Timeout', ':=', ?)",
			radiusGroup.RadiusGroupName, radiusGroup.IdleTimeout).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to insert Idle-Timeout into Radius radgroupreply on update")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Could not update Radius Group in radius (radgroupreply)",
			})
		}
	}

	if radiusGroup.Bandwidth != "" {
		if err := db.RadiusDB.Exec("INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (?, 'Mikrotik-Rate-Limit', ':=', ?)",
			radiusGroup.RadiusGroupName, radiusGroup.Bandwidth).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to insert Bandwidth into Radius radgroupreply on update")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Could not update Radius Group in radius (radgroupreply)",
			})
		}
	}

	tx.Commit()

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Radius Group updated successfully",
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

	tx := db.DB.Begin()
	if err := tx.Delete(&radiusGroup).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to delete Radius Group from PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not delete Radius Group",
		})
	}

	if err := db.RadiusDB.Exec("DELETE FROM radgroupcheck WHERE groupname=?", radiusGroup.RadiusGroupName).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to delete Radius Group from radgroupcheck in Radius DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not delete Radius Group in radius",
		})
	}

	if err := db.RadiusDB.Exec("DELETE FROM radgroupreply WHERE groupname=?", radiusGroup.RadiusGroupName).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to delete Radius Group from radgroupreply in Radius DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Could not delete Radius Group in radius",
		})
	}

	tx.Commit()

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Radius Group deleted successfully",
	})
}

// http/controllers/captive_user.go

package controllers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/http/responses"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
	"tedalogger-backend/providers/validation"
)

func RegisterCaptiveUser(c *fiber.Ctx) error {
	var req requests.CaptiveUserRegisterRequest

	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Captive User register request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for Captive User register request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation error: " + err.Error(),
		})
	}

	var portal models.Portal
	if err := db.DB.Where("portal_id = ?", req.PortalID).First(&portal).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Portal not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to find Portal in database")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	var signupComponents []models.PortalComponent
	if err := json.Unmarshal(portal.SignupComponents, &signupComponents); err != nil {
		logger.Logger.WithError(err).Error("Failed to unmarshal SignupComponents")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Error processing portal components",
		})
	}

	requiredFields := make(map[string]bool)
	tcknValidationRequired := false
	tcknData := struct {
		TCKN      string
		FirstName string
		LastName  string
		BirthYear int
	}{}

	for _, component := range signupComponents {
		normalizedLabel := strings.ToLower(strings.TrimSpace(component.Label))
		if component.Required {
			requiredFields[normalizedLabel] = true
		}

		if normalizedLabel == "tckn" && component.Required {
			tcknValidationRequired = true

			if val, exists := req.DynamicFields["tckn"]; exists {
				if str, ok := val.(string); ok {
					tcknData.TCKN = strings.TrimSpace(str)
				}
			}
			if val, exists := req.DynamicFields["first-name"]; exists {
				if str, ok := val.(string); ok {
					tcknData.FirstName = strings.TrimSpace(str)
				}
			}
			if val, exists := req.DynamicFields["last-name"]; exists {
				if str, ok := val.(string); ok {
					tcknData.LastName = strings.TrimSpace(str)
				}
			}
			if val, exists := req.DynamicFields["birth-year"]; exists {
				switch v := val.(type) {
				case float64:
					tcknData.BirthYear = int(v)
				case int:
					tcknData.BirthYear = v
				case string:
					if intVal, err := strconv.Atoi(v); err == nil {
						tcknData.BirthYear = intVal
					}
				default:
					logger.Logger.Error("Invalid type for birth-year; expected int")
					return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
						Error:   true,
						Message: "Invalid type for birth-year; expected int",
					})
				}
			}
		}
	}

	logger.Logger.Infof("Received dynamic_fields for PortalID %s", req.PortalID)

	for field := range requiredFields {
		if _, exists := req.DynamicFields[field]; !exists {
			logger.Logger.Errorf("Missing required field: %s", field)
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Missing required field: " + field,
			})
		}
	}

	if tcknValidationRequired {
		if tcknData.TCKN == "" || tcknData.FirstName == "" || tcknData.LastName == "" || tcknData.BirthYear == 0 {
			logger.Logger.Error("Missing information for ID verification")
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Missing information for ID verification",
			})
		}

		logger.Logger.Infof("Validating identity for TCKN: %s", tcknData.TCKN)
		valid, err := validation.ValidateIdentity(tcknData.TCKN, tcknData.FirstName, tcknData.LastName, tcknData.BirthYear)
		if err != nil {
			logger.Logger.WithError(err).Error("Error during ID verification")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Error during ID verification",
			})
		}

		if !valid {
			logger.Logger.Warnf("ID verification failed for TCKN: %s", tcknData.TCKN)
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "ID verification failed",
			})
		}
	}

	firstName := ""
	if val, exists := req.DynamicFields["first-name"]; exists {
		if str, ok := val.(string); ok {
			firstName = strings.TrimSpace(str)
		}
	}

	lastName := ""
	if val, exists := req.DynamicFields["last-name"]; exists {
		if str, ok := val.(string); ok {
			lastName = strings.TrimSpace(str)
		}
	}

	tckn := ""
	if val, exists := req.DynamicFields["tckn"]; exists {
		if str, ok := val.(string); ok {
			tckn = strings.TrimSpace(str)
		}
	}

	var birthYearPtr *int
	if val, exists := req.DynamicFields["birth-year"]; exists {
		switch v := val.(type) {
		case float64:
			y := int(v)
			birthYearPtr = &y
		case int:
			y := v
			birthYearPtr = &y
		case string:
			if intVal, err := strconv.Atoi(v); err == nil {
				y := intVal
				birthYearPtr = &y
			}
		}
	}

	username := ""
	if val, exists := req.DynamicFields["username"]; exists {
		if str, ok := val.(string); ok {
			username = strings.TrimSpace(str)
		}
	}

	email := ""
	if val, exists := req.DynamicFields["email"]; exists {
		if str, ok := val.(string); ok {
			email = strings.TrimSpace(str)
		}
	}

	var phonePtr *string
	if val, exists := req.DynamicFields["phone-number"]; exists {
		if str, ok := val.(string); ok {
			trimmed := strings.TrimSpace(str)
			if trimmed != "" {
				phoneStr := trimmed
				phonePtr = &phoneStr
			}
		}
	}

	passwordRaw := ""
	if val, exists := req.DynamicFields["password"]; exists {
		if str, ok := val.(string); ok {
			passwordRaw = strings.TrimSpace(str)
		}
	}

	var hashedPassword *string
	if passwordRaw != "" {
		hashed, err := bcrypt.GenerateFromPassword([]byte(passwordRaw), bcrypt.DefaultCost)
		if err != nil {
			logger.Logger.WithError(err).Error("Failed to hash password")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Error processing password",
			})
		}
		hashedStr := string(hashed)
		hashedPassword = &hashedStr
	}

	var otpCode *string
	var otpExpiresAt *time.Time
	if portal.OtpEnabled {
		fixedOTP := "1234"
		otpCode = &fixedOTP

		location, err := time.LoadLocation("Europe/Istanbul")
		if err != nil {
			logger.Logger.WithError(err).Error("Failed to load Turkey time zone")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to process time zone",
			})
		}

		expiry := time.Now().In(location).Add(5 * time.Minute) // OTP valid for 5 minutes
		otpExpiresAt = &expiry

		logger.Logger.Infof("Fixed OTP code set to: %s for user", *otpCode)
	}

	captiveUser := models.CaptiveUser{
		PortalID:      req.PortalID,
		TCKN:          &tckn,
		FirstName:     &firstName,
		LastName:      &lastName,
		BirthDate:     birthYearPtr,
		Username:      nil, // To be set after creation if not provided
		Password:      hashedPassword,
		Email:         &email,
		Phone:         phonePtr,
		RadiusGroup:   portal.RadiusGroupName,
		NASName:       portal.NasName,
		OTPCode:       otpCode,
		OTPExpiresAt:  otpExpiresAt,
		IsOTPVerified: false,
	}

	tx := db.DB.Begin()
	if tx.Error != nil {
		logger.Logger.WithError(tx.Error).Error("Failed to begin transaction")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	if err := tx.Create(&captiveUser).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to create CaptiveUser in PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to create user",
		})
	}

	logger.Logger.Infof("Created CaptiveUser with ID: %d", captiveUser.ID)

	if username == "" {
		userIDStr := strconv.FormatUint(uint64(captiveUser.ID), 10)
		captiveUser.Username = &userIDStr
	} else {
		captiveUser.Username = &username
	}

	if err := tx.Save(&captiveUser).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to set Username for CaptiveUser")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to create user",
		})
	}

	var nas models.NAS
	if err := db.RadiusDB.Where("nasname = ?", portal.NasName).First(&nas).Error; err != nil {
		tx.Rollback()
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Logger.Errorf("NAS with nasname '%s' not found in Radius DB", portal.NasName)
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "NAS configuration not found in Radius server",
			})
		}
		logger.Logger.WithError(err).Error("Failed to fetch NAS from Radius DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch NAS configuration",
		})
	}

	if captiveUser.Password != nil && *captiveUser.Password != "" {
		if err := db.RadiusDB.Exec(`
			INSERT INTO radcheck (username, attribute, op, value)
			VALUES (?, 'Cleartext-Password', ':=', ?)`,
			*captiveUser.Username, *captiveUser.Password).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to add user to radcheck for password")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to add user to Radius authentication",
			})
		}
	}

	if nas.Nasname != "" {
		if err := db.RadiusDB.Exec(`
			INSERT INTO radcheck (username, attribute, op, value)
			VALUES (?, 'NAS-IP-Address', '==', ?)`,
			*captiveUser.Username, nas.Nasname).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to add user to radcheck for NAS-IP-Address")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to associate user with NAS in Radius",
			})
		}
	}

	if captiveUser.RadiusGroup != "" {
		if err := db.RadiusDB.Exec(`
			INSERT INTO radusergroup (username, groupname, priority)
			VALUES (?, ?, ?)`,
			*captiveUser.Username, captiveUser.RadiusGroup, 1).Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to add user to radusergroup")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to assign user to Radius group",
			})
		}
	}

	if err := tx.Commit().Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to commit transaction for CaptiveUser registration")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Registration process could not be completed",
		})
	}

	if portal.OtpEnabled {
		logger.Logger.Info("Fixed OTP sent to user (simulation)")

		return c.Status(http.StatusOK).JSON(responses.SuccessResponse{
			Error:   false,
			Message: "OTP sent. Please enter the OTP code.",
			Data:    map[string]interface{}{"user_id": captiveUser.ID},
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User created successfully",
		Data:    map[string]interface{}{"user_id": captiveUser.ID},
	})
}

func VerifyOTP(c *fiber.Ctx) error {
	var req requests.VerifyOTPRequest

	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Verify OTP request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	if req.UserID == 0 || strings.TrimSpace(req.OTP) == "" {
		logger.Logger.Error("Missing user_id or OTP in Verify OTP request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User ID and OTP are required",
		})
	}

	var user models.CaptiveUser
	if err := db.DB.Where("id = ?", req.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "User not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to find CaptiveUser in database")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	logger.Logger.Infof("Verifying OTP for user ID: %d", user.ID)

	var portal models.Portal
	if err := db.DB.Where("portal_id = ?", user.PortalID).First(&portal).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to find Portal for CaptiveUser")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	if !portal.OtpEnabled {
		logger.Logger.Warnf("OTP verification attempted for portal without OTP enabled: %s", portal.PortalID)
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "OTP verification is not enabled for this portal",
		})
	}

	if user.OTPExpiresAt == nil || user.OTPCode == nil {
		logger.Logger.Error("OTPExpiresAt or OTPCode is nil for user")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "OTP code or expiration time is not set",
		})
	}

	providedOTP := strings.TrimSpace(req.OTP)
	actualOTP := *user.OTPCode
	otpExpiry := *user.OTPExpiresAt

	if providedOTP != actualOTP {
		logger.Logger.Warnf("OTP verification failed for user ID: %d", user.ID)
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "OTP verification failed or expired",
		})
	}

	if time.Now().After(otpExpiry) {
		logger.Logger.Warnf("OTP expired for user ID: %d", user.ID)
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "OTP verification failed or expired",
		})
	}

	user.IsOTPVerified = true
	if err := db.DB.Save(&user).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to update OTP verification status")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Error during OTP verification",
		})
	}

	logger.Logger.Infof("OTP successfully verified for user ID: %d", user.ID)

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "OTP successfully verified",
		Data:    map[string]interface{}{"user_id": user.ID},
	})
}

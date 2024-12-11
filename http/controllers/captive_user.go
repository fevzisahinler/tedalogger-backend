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

// RegisterCaptiveUser handles user registration for captive portals
func RegisterCaptiveUser(c *fiber.Ctx) error {
	var req requests.CaptiveUserRegisterRequest

	// Parse the request body into CaptiveUserRegisterRequest struct
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Captive User register request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	// Validate the request
	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for Captive User register request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation error: " + err.Error(),
		})
	}

	// Find the Portal by PortalID without logging the entire portal
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

	// Parse SignupComponents to determine required fields
	var signupComponents []models.PortalComponent
	if err := json.Unmarshal(portal.SignupComponents, &signupComponents); err != nil {
		logger.Logger.WithError(err).Error("Failed to unmarshal SignupComponents")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Error processing portal components",
		})
	}

	// Initialize variables for dynamic field mapping
	requiredFields := make(map[string]bool)
	tcknValidationRequired := false
	tcknData := struct {
		TCKN      string
		FirstName string
		LastName  string
		BirthYear int
	}{}

	// Determine required fields and check if tckn validation is needed
	for _, component := range signupComponents {
		normalizedLabel := strings.ToLower(strings.TrimSpace(component.Label))
		if component.Required {
			requiredFields[normalizedLabel] = true
		}

		// Check if tckn is present and required
		if normalizedLabel == "tckn" && component.Required {
			tcknValidationRequired = true

			// Extract TCKN, FirstName, LastName, BirthYear
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
					// Unsupported type
					logger.Logger.Error("Invalid type for birth-year; expected int")
					return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
						Error:   true,
						Message: "Invalid type for birth-year; expected int",
					})
				}
			}
		}
	}

	// Log received dynamic fields for debugging (limited logging)
	logger.Logger.Infof("Received dynamic_fields for PortalID %s", req.PortalID)

	// Validate required fields presence
	for field := range requiredFields {
		if _, exists := req.DynamicFields[field]; !exists {
			logger.Logger.Errorf("Missing required field: %s", field)
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Missing required field: " + field,
			})
		}
	}

	// If tckn validation is required, perform it
	if tcknValidationRequired {
		if tcknData.TCKN == "" || tcknData.FirstName == "" || tcknData.LastName == "" || tcknData.BirthYear == 0 {
			logger.Logger.Error("Missing information for ID verification")
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Missing information for ID verification",
			})
		}

		logger.Logger.Infof("Validating identity for TCKN: %s", tcknData.TCKN)
		// Perform real ID verification
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

	// Extract necessary fields from dynamic_fields directly
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

	// Handle birth-year field
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

	// Handle phone-number field
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

	// Hash the password if provided
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

	// Handle OTP if enabled
	var otpCode *string
	var otpExpiresAt *time.Time
	if portal.OtpEnabled {
		// Set OTP code to "1234"
		fixedOTP := "1234"
		otpCode = &fixedOTP

		// Load Turkey timezone
		location, err := time.LoadLocation("Europe/Istanbul")
		if err != nil {
			logger.Logger.WithError(err).Error("Failed to load Turkey time zone")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to process time zone",
			})
		}

		// Set OTP expiration time to Turkey timezone
		expiry := time.Now().In(location).Add(5 * time.Minute) // OTP valid for 5 minutes
		otpExpiresAt = &expiry

		// Log OTP generation
		logger.Logger.Infof("Fixed OTP code set to: %s for user", *otpCode)
	}

	// Create CaptiveUser instance without Username and Phone
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

	// Begin a transaction
	tx := db.DB.Begin()
	if tx.Error != nil {
		logger.Logger.WithError(tx.Error).Error("Failed to begin transaction")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	// Create the CaptiveUser
	if err := tx.Create(&captiveUser).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to create CaptiveUser in PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to create user",
		})
	}

	// Log the assigned ID for debugging
	logger.Logger.Infof("Created CaptiveUser with ID: %d", captiveUser.ID)

	// Assign Username as provided or user ID if not provided
	if username == "" {
		userIDStr := strconv.FormatUint(uint64(captiveUser.ID), 10)
		captiveUser.Username = &userIDStr
	} else {
		captiveUser.Username = &username
	}

	// Do NOT assign Phone if phonePtr is nil
	// Phone is already set to the provided value or left as nil

	// Save the Username (either provided or generated) immediately
	if err := tx.Save(&captiveUser).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to set Username for CaptiveUser")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to create user",
		})
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to commit transaction for CaptiveUser registration")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Registration process could not be completed",
		})
	}

	// Send OTP if enabled
	if portal.OtpEnabled {
		// Simulate OTP sending (replace with actual sending logic)
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

// VerifyOTP handles OTP verification for Captive Users
func VerifyOTP(c *fiber.Ctx) error {
	var req requests.VerifyOTPRequest

	// Parse the request body into VerifyOTPRequest struct
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Verify OTP request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	// Check for required fields
	if req.UserID == 0 || strings.TrimSpace(req.OTP) == "" {
		logger.Logger.Error("Missing user_id or OTP in Verify OTP request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User ID and OTP are required",
		})
	}

	// Find the CaptiveUser by ID
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

	// Check if OTP is enabled for the portal
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

	// Ensure OTPExpiresAt and OTPCode are not nil
	if user.OTPExpiresAt == nil || user.OTPCode == nil {
		logger.Logger.Error("OTPExpiresAt or OTPCode is nil for user")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "OTP code or expiration time is not set",
		})
	}

	// Validate the OTP
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

	// Update the user to mark OTP as verified
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

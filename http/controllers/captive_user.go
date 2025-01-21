package controllers

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"tedalogger-backend/config"
	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/http/responses"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
	"tedalogger-backend/providers/otp"
	"tedalogger-backend/providers/validation"
)

var otpProvider otp.OTPProvider

func init() {
	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Logger.Errorf("Failed to load config: %v", err)
	}
	otpProvider = otp.NewSimpleOTPProvider(6, cfg.OTPExpireSeconds)
}

func ResendOTP(c *fiber.Ctx) error {
	type ResendOTPRequest struct {
		UserID uint `json:"user_id" validate:"required"`
	}

	var req ResendOTPRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Resend OTP request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	// Basit validasyon
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation error: " + err.Error(),
		})
	}

	// 1. User bulun
	var user models.CaptiveUser
	if err := db.DB.Where("id = ?", req.UserID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Logger.Warnf("User not found for ResendOTP, user_id=%d", req.UserID)
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "User not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to find user for ResendOTP in database")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	logger.Logger.Infof("Resending OTP for user ID: %d", user.ID)

	// 2. Portal bulun
	var portal models.Portal
	if err := db.DB.Where("portal_id = ?", user.PortalID).First(&portal).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to find Portal for CaptiveUser in ResendOTP")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}
	if !portal.OtpEnabled {
		logger.Logger.Warnf("ResendOTP attempted for portal without OTP enabled: %s", portal.PortalID)
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "OTP is not enabled for this portal",
		})
	}

	// 3. OTP tekrar gönder
	cfg, _ := config.LoadConfig()
	if err := otpProvider.RequestOTP(&user, cfg); err != nil {
		logger.Logger.WithError(err).Error("Failed to re-generate/send OTP on ResendOTP")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to send OTP",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "OTP resent successfully. Please check your phone.",
		Data: map[string]interface{}{
			"user_id": user.ID,
		},
	})
}

func LoginCaptiveUser(c *fiber.Ctx) error {
	var req requests.CaptiveUserLoginRequest

	// 1. Body’den JSON parse
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Captive User Login request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	// 2. Validasyon
	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for Captive User Login request")
		var ve validator.ValidationErrors
		if errors.As(err, &ve) {
			var errorMsgs []string
			for _, fe := range ve {
				errorMsg := fmt.Sprintf("Field '%s' failed on the '%s' tag", fe.Field(), fe.Tag())
				errorMsgs = append(errorMsgs, errorMsg)
			}
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: strings.Join(errorMsgs, ", "),
			})
		}
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation error",
		})
	}

	// 3. Portal bilgisi
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

	// 4. loginComponents parse et
	var loginComponents []models.PortalComponent
	if err := json.Unmarshal(portal.LoginComponents, &loginComponents); err != nil {
		logger.Logger.WithError(err).Error("Failed to unmarshal LoginComponents")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Error processing portal components",
		})
	}

	// 5. Zorunlu alanları bul
	requiredFields := make(map[string]bool)
	for _, component := range loginComponents {
		normalizedLabel := strings.ToLower(strings.TrimSpace(component.Label))
		if component.Required {
			requiredFields[normalizedLabel] = true
		}
	}

	// 6. Zorunlu alanlar dolu mu?
	for field := range requiredFields {
		if _, exists := req.DynamicFields[field]; !exists {
			logger.Logger.Errorf("Missing required field: %s", field)
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Missing required field: " + field,
			})
		}
	}

	// 7. Beklenmeyen alan var mı?
	for field := range req.DynamicFields {
		normalizedField := strings.ToLower(strings.TrimSpace(field))
		if _, exists := requiredFields[normalizedField]; !exists {
			logger.Logger.Errorf("Unexpected field: %s", field)
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Unexpected field: " + field,
			})
		}
	}

	// 8. DB'den kullanıcıyı bul
	var user models.CaptiveUser
	query := db.DB.Where("portal_id = ?", req.PortalID)

	for key, value := range req.DynamicFields {
		column := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(key)), "-", "_")
		switch v := value.(type) {
		case string:
			if column == "password" {
				continue
			}
			query = query.Where(fmt.Sprintf("%s = ?", column), v)
		case float64:
			// JSON parse olduğunda rakamlar float64 gelebiliyor
			query = query.Where(fmt.Sprintf("%s = ?", column), strconv.FormatFloat(v, 'f', -1, 64))
		case int:
			query = query.Where(fmt.Sprintf("%s = ?", column), strconv.Itoa(v))
		default:
			logger.Logger.Errorf("Unsupported type for dynamic field: %s", key)
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Unsupported type for field: " + key,
			})
		}
	}

	if err := query.First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Logger.Warnf("User not found with dynamic fields: %+v", req.DynamicFields)
			return c.Status(http.StatusUnauthorized).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Invalid credentials",
			})
		}
		logger.Logger.WithError(err).Error("Failed to find CaptiveUser in database")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	// 9. Parola doğrula
	if user.Password == nil {
		logger.Logger.Error("Password is nil for the user")
		return c.Status(http.StatusUnauthorized).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid credentials",
		})
	}

	inputPassword, ok := req.DynamicFields["password"].(string)
	if !ok {
		logger.Logger.Error("Password field is missing or not a string")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Password is required",
		})
	}

	if *user.Password != inputPassword {
		logger.Logger.Warnf("Password mismatch for user: %s", *user.Username)
		return c.Status(http.StatusUnauthorized).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid credentials",
		})
	}
	logger.Logger.Infof("Local DB user %s authenticated successfully", *user.Username)

	// 10. OTP kontrolü (opsiyonel)
	if portal.OtpEnabled {
		// OTP üret, DB'ye yaz, SMS gönder
		cfg, _ := config.LoadConfig()
		if err := otpProvider.RequestOTP(&user, cfg); err != nil {
			logger.Logger.WithError(err).Error("Failed to generate/send OTP on login")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to send OTP",
			})
		}

		return c.JSON(responses.SuccessResponse{
			Error:   false,
			Message: "Login successful, OTP sent. Please verify.",
			Data: map[string]interface{}{
				"user_id": user.ID,
			},
		})
	}

	// OTP devre dışıysa => direkt başarılı login
	now := time.Now()
	user.LastLoginAt = &now
	if err := db.DB.Save(&user).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to update user login timestamp")
		// hata olsa da devam
	}

	// FortiGate parametreleri (kısaltılmış)
	firewallPostURL := req.FirewallParams["post"]
	if firewallPostURL == "" {
		logger.Logger.Warn("Missing 'post' parameter in firewall_params")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Missing firewall post URL (firewall_params.post)",
		})
	}

	logger.Logger.Infof("FortiGate authentication succeeded for user: %s", *user.Username)

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Login successful (no OTP required)",
		Data: map[string]interface{}{
			"user_id": user.ID,
		},
	})
}

func RegisterCaptiveUser(c *fiber.Ctx) error {
	var req requests.CaptiveUserRegisterRequest

	// 1. İstek gövdesinden verileri al
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Captive User register request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	// 2. Validasyon
	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for Captive User register request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation error: " + err.Error(),
		})
	}

	// 3. Portal bilgisi
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

	// 4. signupComponents parse
	var signupComponents []models.PortalComponent
	if err := json.Unmarshal(portal.SignupComponents, &signupComponents); err != nil {
		logger.Logger.WithError(err).Error("Failed to unmarshal SignupComponents")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Error processing portal components",
		})
	}

	// 5. Gerekli alanlar
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

		// TCKN Validation isteniyorsa
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

	// 6. Gerekli alanlar doldurulmuş mu
	for field := range requiredFields {
		if _, exists := req.DynamicFields[field]; !exists {
			logger.Logger.Errorf("Missing required field: %s", field)
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Missing required field: " + field,
			})
		}
	}

	// 7. TCKN doğrulaması (opsiyonel)
	if tcknValidationRequired {
		if tcknData.TCKN == "" || tcknData.FirstName == "" || tcknData.LastName == "" || tcknData.BirthYear == 0 {
			logger.Logger.Error("Missing information for ID verification")
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Missing information for ID verification",
			})
		}

		logger.Logger.Infof("Validating identity for TCKN: %s", tcknData.TCKN)
		valid, err := validation.ValidateIdentity(
			tcknData.TCKN,
			tcknData.FirstName,
			tcknData.LastName,
			tcknData.BirthYear,
		)
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

	// 8. Dynamic Fields’i parse
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

	// 9. Parola
	passwordRaw := ""
	if val, exists := req.DynamicFields["password"]; exists {
		if str, ok := val.(string); ok {
			passwordRaw = strings.TrimSpace(str)
		}
	}
	var cleartextPassword *string
	if passwordRaw != "" {
		cleartextPassword = &passwordRaw
	}

	// 10. CaptiveUser nesnesi
	captiveUser := models.CaptiveUser{
		PortalID:      req.PortalID,
		TCKN:          &tckn,
		FirstName:     &firstName,
		LastName:      &lastName,
		BirthDate:     birthYearPtr,
		Username:      nil,               // sonra dolduracağız
		Password:      cleartextPassword, // plaintext saklanıyor (demo amaçlı)
		Email:         &email,
		Phone:         phonePtr,
		RadiusGroup:   portal.RadiusGroupName,
		NASName:       portal.NasName,
		OTPCode:       nil,
		OTPExpiresAt:  nil,
		IsOTPVerified: false,
	}

	// 11. Transaction
	tx := db.DB.Begin()
	if tx.Error != nil {
		logger.Logger.WithError(tx.Error).Error("Failed to begin transaction")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	// 12. Kaydet
	if err := tx.Create(&captiveUser).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to create CaptiveUser in PostgreSQL")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to create user",
		})
	}
	logger.Logger.Infof("Created CaptiveUser with ID: %d", captiveUser.ID)

	// Username boş ise ID'yi atayalım
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

	// 13. Radius entegrasyonu (kısaltılmış örnek)
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

	// radcheck tablosuna Cleartext-Password yaz
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

	// NAS-IP-Address
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

	// radusergroup
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

	// 14. Commit
	if err := tx.Commit().Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to commit transaction for CaptiveUser registration")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Registration process could not be completed",
		})
	}

	// 15. Dinamik OTP akışı
	if portal.OtpEnabled {
		logger.Logger.Infof("Portal OTP is enabled, generating dynamic OTP for user ID=%d", captiveUser.ID)

		cfg, _ := config.LoadConfig()
		if err := otpProvider.RequestOTP(&captiveUser, cfg); err != nil {
			logger.Logger.WithError(err).Error("Failed to generate/send OTP on register")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to send OTP",
			})
		}

		return c.Status(http.StatusOK).JSON(responses.SuccessResponse{
			Error:   false,
			Message: "User created. OTP sent. Please enter the OTP code.",
			Data:    map[string]interface{}{"user_id": captiveUser.ID},
		})
	}

	return c.Status(http.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User created successfully (no OTP required)",
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

	// OTP Doğrulama
	if !otpProvider.ValidateOTP(providedOTP, actualOTP, otpExpiry) {
		logger.Logger.Warnf("OTP verification failed or expired for user ID: %d", user.ID)
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "OTP verification failed or expired",
		})
	}

	// Doğrulama başarılı
	user.IsOTPVerified = true
	user.OTPCode = nil
	user.OTPExpiresAt = nil
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

func VerifyLoginOTP(c *fiber.Ctx) error {
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

	logger.Logger.Infof("Verifying Login OTP for user ID: %d", user.ID)

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

	// OTP Doğrulama (expire süresini kontrol edebilirsiniz)
	if !otpProvider.ValidateOTP(providedOTP, actualOTP, *user.OTPExpiresAt) {
		logger.Logger.Warnf("OTP verification failed or expired for user ID: %d", user.ID)
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "OTP verification failed or expired",
		})
	}

	// Doğrulama başarılı
	user.IsOTPVerified = true
	user.OTPCode = nil
	user.OTPExpiresAt = nil
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

func CreateCaptiveUser(c *fiber.Ctx) error {
	var req requests.CaptiveUserRegisterRequest

	// 1. İstek Gövdesini Parse Et
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse CreateCaptiveUser request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}

	// 2. Validasyon Yap
	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for CreateCaptiveUser request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation error: " + err.Error(),
		})
	}

	// 3. Portal Bilgisini Al
	var portal models.Portal
	if err := db.DB.Where("portal_id = ?", req.PortalID).First(&portal).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Logger.Errorf("Portal not found with ID: %s", req.PortalID)
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

	// 4. SignupComponents Parse Et
	var signupComponents []models.PortalComponent
	if err := json.Unmarshal(portal.SignupComponents, &signupComponents); err != nil {
		logger.Logger.WithError(err).Error("Failed to unmarshal SignupComponents")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Error processing portal components",
		})
	}

	// 5. Gerekli Alanları Belirle
	requiredFields := make(map[string]bool)
	for _, comp := range signupComponents {
		if comp.Required {
			requiredFields[strings.ToLower(strings.TrimSpace(comp.Label))] = true
		}
	}

	// 6. Gerekli Alanların Var Olduğunu Kontrol Et
	for rf := range requiredFields {
		if _, exists := req.DynamicFields[rf]; !exists {
			logger.Logger.Errorf("Missing required field: %s", rf)
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: fmt.Sprintf("Missing required field: %s", rf),
			})
		}
	}

	// 7. CaptiveUser Modelini Oluştur
	captiveUser := models.CaptiveUser{
		PortalID:      req.PortalID,
		IsOTPVerified: true,
	}

	// 8. Dynamic Fields'i İşle
	var cleartextPassword string
	for key, val := range req.DynamicFields {
		fieldName := strings.ToLower(strings.TrimSpace(key))

		switch fieldName {
		case "first-name":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				captiveUser.FirstName = &strVal
			}
		case "last-name":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				captiveUser.LastName = &strVal
			}
		case "tckn":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				captiveUser.TCKN = &strVal
			}
		case "birth-year":
			switch typedVal := val.(type) {
			case float64:
				y := int(typedVal)
				captiveUser.BirthDate = &y
			case int:
				captiveUser.BirthDate = &typedVal
			case string:
				if y, err := strconv.Atoi(typedVal); err == nil {
					captiveUser.BirthDate = &y
				}
			}
		case "username":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				if strVal != "" {
					captiveUser.Username = &strVal
				}
			}
		case "password":
			if strVal, ok := val.(string); ok && strVal != "" {
				cleartextPassword = strVal
				// Hash'li halini captive_user tablosunda sakla
				hashed, err := bcrypt.GenerateFromPassword([]byte(strVal), bcrypt.DefaultCost)
				if err != nil {
					logger.Logger.WithError(err).Error("Failed to hash password")
					return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
						Error:   true,
						Message: "Error processing password",
					})
				}
				hashedStr := string(hashed)
				captiveUser.Password = &hashedStr
			}
		case "email":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				captiveUser.Email = &strVal
			}
		case "phone", "phone-number":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				captiveUser.Phone = &strVal
			}
		case "nas-name":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				captiveUser.NASName = strVal
			}
		case "radius-group":

		default:
			logger.Logger.Infof("Unhandled field (Create) -> %s: %v", fieldName, val)
		}
	}

	if portal.RadiusGroupName != "" {
		captiveUser.RadiusGroup = portal.RadiusGroupName
	}
	// 9. Transaction Başlat (PostgreSQL ve RadiusDB için)
	tx := db.DB.Begin()
	if tx.Error != nil {
		logger.Logger.WithError(tx.Error).Error("Failed to begin transaction for CreateCaptiveUser")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Transaction error",
		})
	}

	if err := tx.Create(&captiveUser).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to create CaptiveUser in DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to create user",
		})
	}

	logger.Logger.Infof("Created CaptiveUser with ID: %d", captiveUser.ID)

	// 11. RadiusDB Transaction Başlat
	radiusTx := db.RadiusDB.Begin()
	if radiusTx.Error != nil {
		tx.Rollback()
		logger.Logger.WithError(radiusTx.Error).Error("Failed to begin radius transaction")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Radius transaction error",
		})
	}

	if captiveUser.Username != nil && cleartextPassword != "" {
		if err := radiusTx.Exec(`
			INSERT INTO radcheck (username, attribute, op, value)
			VALUES (?, 'Cleartext-Password', ':=', ?)`,
			*captiveUser.Username, cleartextPassword).Error; err != nil {
			radiusTx.Rollback()
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to add user to radcheck (password)")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to add user to Radius authentication",
			})
		}
	}

	nasIP := portal.NasName // Portal modelinizde NasName alanının doğru şekilde tanımlandığını varsayıyoruz
	if nasIP != "" && captiveUser.Username != nil {
		if err := radiusTx.Exec(`
			INSERT INTO radcheck (username, attribute, op, value)
			VALUES (?, 'NAS-IP-Address', '==', ?)`,
			*captiveUser.Username, nasIP).Error; err != nil {
			radiusTx.Rollback()
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to add user to radcheck (NAS-IP-Address)")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to associate user with NAS in Radius",
			})
		}
	}

	if portal.RadiusGroupName != "" && captiveUser.Username != nil {
		if err := radiusTx.Exec(`
			INSERT INTO radusergroup (username, groupname, priority)
			VALUES (?, ?, 1)`,
			*captiveUser.Username, portal.RadiusGroupName).Error; err != nil {
			radiusTx.Rollback()
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to add user to radusergroup")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to assign user to Radius group",
			})
		}
	}

	// 15. RadiusDB Transaction'ını Commit Et
	if err := radiusTx.Commit().Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to commit radius transaction")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to commit radius transaction",
		})
	}

	// 16. PostgreSQL Transaction'ını Commit Et
	if err := tx.Commit().Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to commit transaction for CreateCaptiveUser")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Transaction commit error",
		})
	}

	// 17. Başarılı Yanıt Dön
	return c.Status(http.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User created successfully",
		Data: map[string]interface{}{
			"user_id":         captiveUser.ID,
			"is_otp_verified": captiveUser.IsOTPVerified,
		},
	})
}

func GetCaptiveUser(c *fiber.Ctx) error {
	idParam := c.Params("id")
	if idParam == "" {
		logger.Logger.Error("Missing user ID param in GetCaptiveUser")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User ID parameter is required",
		})
	}

	userID, err := strconv.Atoi(idParam)
	if err != nil {
		logger.Logger.WithError(err).Error("Invalid user ID param in GetCaptiveUser")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid user ID",
		})
	}

	var user models.CaptiveUser
	if err := db.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Logger.Warnf("User not found with ID: %d", userID)
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "User not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to get CaptiveUser from DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User retrieved successfully",
		Data:    user,
	})
}

func UpdateCaptiveUser(c *fiber.Ctx) error {
	idParam := c.Params("id")
	if idParam == "" {
		logger.Logger.Error("Missing user ID param in UpdateCaptiveUser")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User ID parameter is required",
		})
	}

	userID, err := strconv.Atoi(idParam)
	if err != nil {
		logger.Logger.WithError(err).Error("Invalid user ID param in UpdateCaptiveUser")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid user ID",
		})
	}

	var existingUser models.CaptiveUser
	if err := db.DB.Where("id = ?", userID).First(&existingUser).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Logger.Warnf("User not found with ID %d for update", userID)
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "User not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to find CaptiveUser for update in DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	// Request parse
	var req requests.CaptiveUserRegisterRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse UpdateCaptiveUser request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid input",
		})
	}
	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for UpdateCaptiveUser")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation error: " + err.Error(),
		})
	}

	// Portal (yeni mi, aynı mı?)
	var portal models.Portal
	portalID := req.PortalID
	if portalID == "" {
		portalID = existingUser.PortalID // eğer request gelmediyse eskisi kalsın
	}

	if err := db.DB.Where("portal_id = ?", portalID).First(&portal).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Logger.Errorf("Portal not found with ID: %s", portalID)
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Portal not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to find Portal in database for update")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	var signupComponents []models.PortalComponent
	if err := json.Unmarshal(portal.SignupComponents, &signupComponents); err != nil {
		logger.Logger.WithError(err).Error("Failed to unmarshal SignupComponents in update")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Error processing portal components",
		})
	}

	// Required alan kontrol
	requiredFields := make(map[string]bool)
	for _, comp := range signupComponents {
		if comp.Required {
			requiredFields[strings.ToLower(strings.TrimSpace(comp.Label))] = true
		}
	}
	for rf := range requiredFields {
		if _, exists := req.DynamicFields[rf]; !exists {
			logger.Logger.Errorf("Missing required field: %s in update", rf)
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: fmt.Sprintf("Missing required field: %s", rf),
			})
		}
	}

	existingUser.PortalID = portalID
	existingUser.IsOTPVerified = true // yine OTP yok

	var cleartextPassword string

	for key, val := range req.DynamicFields {
		fieldName := strings.ToLower(strings.TrimSpace(key))
		switch fieldName {
		case "first-name":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				existingUser.FirstName = &strVal
			}
		case "last-name":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				existingUser.LastName = &strVal
			}
		case "tckn":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				existingUser.TCKN = &strVal
			}
		case "birth-year":
			switch typedVal := val.(type) {
			case float64:
				y := int(typedVal)
				existingUser.BirthDate = &y
			case int:
				existingUser.BirthDate = &typedVal
			case string:
				if y, err := strconv.Atoi(typedVal); err == nil {
					existingUser.BirthDate = &y
				}
			}
		case "username":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				if strVal != "" {
					existingUser.Username = &strVal
				}
			}
		case "password":
			if strVal, ok := val.(string); ok && strVal != "" {
				cleartextPassword = strVal
				hashed, err := bcrypt.GenerateFromPassword([]byte(strVal), bcrypt.DefaultCost)
				if err != nil {
					logger.Logger.WithError(err).Error("Failed to hash password during update")
					return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
						Error:   true,
						Message: "Error processing password",
					})
				}
				hashedStr := string(hashed)
				existingUser.Password = &hashedStr
			}
		case "email":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				existingUser.Email = &strVal
			}
		case "phone", "phone-number":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				existingUser.Phone = &strVal
			}
		case "nas-name":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				existingUser.NASName = strVal
			}
		case "radius-group":
			if strVal, ok := val.(string); ok {
				strVal = strings.TrimSpace(strVal)
				existingUser.RadiusGroup = strVal
			}
		default:
			logger.Logger.Infof("Unhandled field (Update) -> %s: %v", fieldName, val)
		}
	}

	existingUser.UpdatedAt = time.Now()

	tx := db.DB.Begin()
	if tx.Error != nil {
		logger.Logger.WithError(tx.Error).Error("Failed to begin transaction for UpdateCaptiveUser")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Transaction error",
		})
	}

	// Kaydı güncelle
	if err := tx.Save(&existingUser).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to update CaptiveUser in DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to update user",
		})
	}

	// Radius DB'de user eski kayıtlardan temizlenip tekrar eklenir
	if existingUser.Username != nil && *existingUser.Username != "" {
		radiusTx := db.RadiusDB.Begin()
		if radiusTx.Error != nil {
			tx.Rollback()
			logger.Logger.WithError(radiusTx.Error).Error("Failed to begin radiusTx in update")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Radius transaction error",
			})
		}

		// Eski radcheck kayıtlarını sil
		if err := radiusTx.Exec("DELETE FROM radcheck WHERE username = ?", *existingUser.Username).Error; err != nil {
			radiusTx.Rollback()
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to delete radcheck records for update")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to remove old radcheck data",
			})
		}

		// Eski radusergroup kayıtlarını sil
		if err := radiusTx.Exec("DELETE FROM radusergroup WHERE username = ?", *existingUser.Username).Error; err != nil {
			radiusTx.Rollback()
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to delete radusergroup records for update")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to remove old radusergroup data",
			})
		}

		// Yeni radcheck -> Cleartext-Password
		if cleartextPassword != "" {
			if err := radiusTx.Exec(
				"INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)",
				*existingUser.Username, cleartextPassword,
			).Error; err != nil {
				radiusTx.Rollback()
				tx.Rollback()
				logger.Logger.WithError(err).Error("Failed to add new radcheck (password)")
				return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Failed to add user to Radius authentication",
				})
			}
		}

		// Yeni radcheck -> NAS-IP-Address
		if existingUser.NASName != "" {
			if err := radiusTx.Exec(
				"INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'NAS-IP-Address', '==', ?)",
				*existingUser.Username, existingUser.NASName,
			).Error; err != nil {
				radiusTx.Rollback()
				tx.Rollback()
				logger.Logger.WithError(err).Error("Failed to add new radcheck (NAS-IP-Address)")
				return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Failed to associate user with NAS in Radius",
				})
			}
		}

		// Yeni radusergroup kaydı
		if existingUser.RadiusGroup != "" {
			if err := radiusTx.Exec(
				"INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)",
				*existingUser.Username, existingUser.RadiusGroup,
			).Error; err != nil {
				radiusTx.Rollback()
				tx.Rollback()
				logger.Logger.WithError(err).Error("Failed to add user to radusergroup after update")
				return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Failed to assign user to Radius group",
				})
			}
		}

		if err := radiusTx.Commit().Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to commit radiusTx in update")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to commit radius transaction",
			})
		}
	}

	if err := tx.Commit().Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to commit transaction for UpdateCaptiveUser")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Transaction commit error",
		})
	}

	logger.Logger.Infof("CaptiveUser with ID %d updated successfully", existingUser.ID)

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User updated successfully",
		Data:    existingUser,
	})
}

func DeleteCaptiveUser(c *fiber.Ctx) error {
	idParam := c.Params("id")
	if idParam == "" {
		logger.Logger.Error("Missing user ID param in DeleteCaptiveUser")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "User ID parameter is required",
		})
	}

	userID, err := strconv.Atoi(idParam)
	if err != nil {
		logger.Logger.WithError(err).Error("Invalid user ID param in DeleteCaptiveUser")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid user ID",
		})
	}

	var user models.CaptiveUser
	if err := db.DB.Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Logger.Warnf("User not found with ID: %d for delete", userID)
			return c.Status(http.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "User not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to find CaptiveUser for delete in DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred",
		})
	}

	tx := db.DB.Begin()
	if tx.Error != nil {
		logger.Logger.WithError(tx.Error).Error("Failed to begin transaction for DeleteCaptiveUser")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Transaction error",
		})
	}

	// CaptiveUser tablosundan sil
	if err := tx.Delete(&user).Error; err != nil {
		tx.Rollback()
		logger.Logger.WithError(err).Error("Failed to delete CaptiveUser in DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to delete user",
		})
	}

	// Radius DB den de sil
	if user.Username != nil && *user.Username != "" {
		radiusTx := db.RadiusDB.Begin()
		if radiusTx.Error != nil {
			tx.Rollback()
			logger.Logger.WithError(radiusTx.Error).Error("Failed to begin radiusTx in delete")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Radius transaction error",
			})
		}

		// radcheck sil
		if err := radiusTx.Exec("DELETE FROM radcheck WHERE username = ?", *user.Username).Error; err != nil {
			radiusTx.Rollback()
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to delete radcheck on user delete")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to remove user from radcheck",
			})
		}

		// radusergroup sil
		if err := radiusTx.Exec("DELETE FROM radusergroup WHERE username = ?", *user.Username).Error; err != nil {
			radiusTx.Rollback()
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to delete radusergroup on user delete")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to remove user from radusergroup",
			})
		}

		if err := radiusTx.Commit().Error; err != nil {
			tx.Rollback()
			logger.Logger.WithError(err).Error("Failed to commit radiusTx in delete")
			return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to commit radius transaction",
			})
		}
	}

	if err := tx.Commit().Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to commit transaction for DeleteCaptiveUser")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Transaction commit error",
		})
	}

	logger.Logger.Infof("CaptiveUser with ID %d deleted successfully", user.ID)

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "User deleted successfully",
		Data: map[string]interface{}{
			"user_id": user.ID,
		},
	})
}

func GetAllCaptiveUsers(c *fiber.Ctx) error {
	var users []models.CaptiveUser

	// DB'den tüm kullanıcıları çekelim
	if err := db.DB.Find(&users).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to fetch all CaptiveUsers from DB")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Unexpected error occurred while fetching users",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "All users retrieved successfully",
		Data:    users,
	})
}

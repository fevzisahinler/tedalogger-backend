// http/controllers/portal.go

package controllers

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/http/responses"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func handleFileUpload(c *fiber.Ctx, formFieldName, storagePath string) (string, error) {
	fileHeader, err := c.FormFile(formFieldName)
	if err != nil {
		return "", nil
	}
	if fileHeader == nil {
		return "", nil
	}

	ext := filepath.Ext(fileHeader.Filename)
	allowedExtensions := map[string]bool{
		".png":  true,
		".jpg":  true,
		".jpeg": true,
	}
	if !allowedExtensions[ext] {
		return "", fmt.Errorf("unsupported file extension: %s", ext)
	}

	src, err := fileHeader.Open()
	if err != nil {
		return "", err
	}
	defer src.Close()

	buffer := make([]byte, 512)
	if _, err := src.Read(buffer); err != nil && err != io.EOF {
		return "", err
	}
	filetype := http.DetectContentType(buffer)
	allowedContentTypes := map[string]bool{
		"image/png":  true,
		"image/jpeg": true,
	}
	if !allowedContentTypes[filetype] {
		return "", fmt.Errorf("unsupported file type: %s", filetype)
	}

	if _, err := src.Seek(0, 0); err != nil {
		return "", err
	}

	hash := md5.New()
	if _, err := io.Copy(hash, src); err != nil {
		return "", err
	}
	md5String := hex.EncodeToString(hash.Sum(nil))
	newFileName := md5String + ext
	savePath := filepath.Join(storagePath, newFileName)

	if err := c.SaveFile(fileHeader, savePath); err != nil {
		return "", err
	}

	return newFileName, nil
}

func CreatePortal(c *fiber.Ctx) error {
	form, err := c.MultipartForm()
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to parse multipart/form for Portal create")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid form-data input",
		})
	}

	var req requests.CreateOrUpdatePortalRequest

	// 1) Metinsel alanları oku ve struct’a at
	//    Örnek: form.Value["portalID"] => []string
	if val, ok := form.Value["portalID"]; ok && len(val) > 0 {
		req.PortalID = val[0]
	}
	if val, ok := form.Value["name"]; ok && len(val) > 0 {
		req.Name = val[0]
	}
	if val, ok := form.Value["radiusGroupName"]; ok && len(val) > 0 {
		req.RadiusGroupName = val[0]
	}
	if val, ok := form.Value["nasName"]; ok && len(val) > 0 {
		req.NasName = val[0]
	}

	// 2) JSON string olarak gelen alanları manuel parse et
	if val, ok := form.Value["loginComponents"]; ok && len(val) > 0 {
		if err := json.Unmarshal([]byte(val[0]), &req.LoginComponents); err != nil {
			logger.Logger.WithError(err).Error("Failed to parse loginComponents JSON")
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Invalid loginComponents JSON",
			})
		}
	}
	if val, ok := form.Value["signupComponents"]; ok && len(val) > 0 {
		if err := json.Unmarshal([]byte(val[0]), &req.SignupComponents); err != nil {
			logger.Logger.WithError(err).Error("Failed to parse signupComponents JSON")
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Invalid signupComponents JSON",
			})
		}
	}
	if val, ok := form.Value["theme"]; ok && len(val) > 0 {
		if err := json.Unmarshal([]byte(val[0]), &req.Theme); err != nil {
			logger.Logger.WithError(err).Error("Failed to parse theme JSON")
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Invalid theme JSON",
			})
		}
	}

	// 3) Boolean alanlar (örnek: otpEnabled)
	if val, ok := form.Value["otpEnabled"]; ok && len(val) > 0 {
		// "true" / "false" stringini parse edelim
		if val[0] == "true" {
			req.OtpEnabled = true
		} else {
			req.OtpEnabled = false
		}
	}

	// 4) Dosyaları yükle (logo + background)
	logoStorage := os.Getenv("LOGO_STORAGE")             // e.g. "storage/logos/"
	backgroundStorage := os.Getenv("BACKGROUND_STORAGE") // e.g. "storage/backgrounds/"

	uploadedLogo, err := handleFileUpload(c, "logo", logoStorage)
	if err != nil {
		logger.Logger.WithError(err).Error("Logo file upload failed")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: err.Error(),
		})
	}

	uploadedBackground, err := handleFileUpload(c, "background", backgroundStorage)
	if err != nil {
		logger.Logger.WithError(err).Error("Background file upload failed")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: err.Error(),
		})
	}

	if uploadedLogo != "" {
		req.Logo = uploadedLogo
	}
	if uploadedBackground != "" {
		req.Background = uploadedBackground
	}

	// 5) Validasyon
	if err := req.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed for Portal create request")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Validation failed",
		})
	}

	// 6) Marshall ve DB'ye kaydet
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
		logger.Logger.WithError(err).Error("Failed to create Portal in DB")
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

	// Parse multipart form for potential file uploads
	if form, err := c.MultipartForm(); err == nil {
		if err := c.BodyParser(&requests.CreateOrUpdatePortalRequest{}); err != nil {
			logger.Logger.WithError(err).Error("Failed to parse Portal update request (multipart form scenario)")
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Invalid input",
			})
		}
		_ = form
	} else {
		if err := c.BodyParser(&requests.CreateOrUpdatePortalRequest{}); err != nil {
			logger.Logger.WithError(err).Error("Failed to parse Portal update request (JSON scenario)")
			return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Invalid input",
			})
		}
	}

	var req requests.CreateOrUpdatePortalRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse Portal update request into struct")
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

	// Handle logo file upload
	logoStorage := os.Getenv("LOGO_STORAGE")
	uploadedLogo, err := handleFileUpload(c, "logo", logoStorage)
	if err != nil {
		logger.Logger.WithError(err).Error("Logo file upload failed (update)")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: err.Error(),
		})
	}

	// Handle background file upload
	backgroundStorage := os.Getenv("BACKGROUND_STORAGE")
	uploadedBackground, err := handleFileUpload(c, "background", backgroundStorage)
	if err != nil {
		logger.Logger.WithError(err).Error("Background file upload failed (update)")
		return c.Status(http.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: err.Error(),
		})
	}

	// Marshal login components
	loginComponentsJSON, err := json.Marshal(req.LoginComponents)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to marshal loginComponents on update")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to process components",
		})
	}

	// Marshal signup components
	signupComponentsJSON, err := json.Marshal(req.SignupComponents)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to marshal signupComponents on update")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to process components",
		})
	}

	// Marshal theme
	themeJSON, err := json.Marshal(req.Theme)
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to marshal theme on update")
		return c.Status(http.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to process theme",
		})
	}

	// Update fields
	portal.PortalID = req.PortalID
	portal.Name = req.Name
	portal.RadiusGroupName = req.RadiusGroupName
	portal.NasName = req.NasName
	portal.LoginComponents = loginComponentsJSON
	portal.SignupComponents = signupComponentsJSON
	portal.Theme = themeJSON
	portal.OtpEnabled = req.OtpEnabled

	// If a new file was uploaded for logo, update it; else keep old one
	if uploadedLogo != "" {
		portal.Logo = uploadedLogo
	}

	// If a new file was uploaded for background, update it; else keep old one
	if uploadedBackground != "" {
		portal.Background = uploadedBackground
	}

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

	// Optional: Remove previously uploaded files from disk if needed.
	// This depends on your policy for file cleanup (not strictly required).
	// Example:
	// if portal.Logo != "" {
	//     os.Remove(filepath.Join(os.Getenv("LOGO_STORAGE"), portal.Logo))
	// }
	// if portal.Background != "" {
	//     os.Remove(filepath.Join(os.Getenv("BACKGROUND_STORAGE"), portal.Background))
	// }

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

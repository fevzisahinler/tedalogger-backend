package controllers

import (
	"errors"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/http/responses"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
	"tedalogger-backend/providers/cryptology"
	"time"
)

const (
	SFTPKeyStoragePath = "/Users/fevzisahinler/Desktop/log-settings/sftp-uploaded-keys/"
	MaxFileSize        = 1 << 20 // 1 MB
)

func CreateLogDestination(c *fiber.Ctx) error {
	req := new(requests.CreateLogDestinationRequest)
	if err := c.BodyParser(req); err != nil {
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

	var hashedPassword string
	if req.Password != "" {
		var err error
		hashedPassword, err = cryptology.HashPassword(req.Password)
		if err != nil {
			logger.Logger.WithError(err).Error("Failed to hash password")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "An unexpected error occurred",
			})
		}
	}

	var sshKeyPath string
	if req.Type == models.SFTP {
		fileHeader, err := c.FormFile("sshKeyFile")
		if err != nil {
			logger.Logger.WithError(err).Error("SSH Key file is required for SFTP")
			return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "SSH Key file is required for SFTP",
			})
		}

		if fileHeader.Size > MaxFileSize {
			return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: fmt.Sprintf("SSH Key file size exceeds %d bytes", MaxFileSize),
			})
		}

		file, err := fileHeader.Open()
		if err != nil {
			logger.Logger.WithError(err).Error("Failed to open uploaded SSH key file")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to process SSH Key file",
			})
		}
		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			logger.Logger.WithError(err).Error("Failed to read SSH key file content")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to read SSH Key file",
			})
		}

		contentStr := strings.TrimSpace(string(content))
		if !strings.HasPrefix(contentStr, "ssh-") && !strings.HasPrefix(contentStr, "-----BEGIN") {
			return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Invalid SSH Key file format",
			})
		}

		if _, err := file.Seek(0, io.SeekStart); err != nil {
			logger.Logger.WithError(err).Error("Failed to seek SSH key file")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to process SSH Key file",
			})
		}

		if err := os.MkdirAll(SFTPKeyStoragePath, os.ModePerm); err != nil {
			logger.Logger.WithError(err).Error("Failed to create SSH key storage directory")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "An unexpected error occurred",
			})
		}

		sshKeyFileName := fmt.Sprintf("sftp-key-%d.pem", time.Now().UnixNano())
		sshKeyPath = filepath.Join(SFTPKeyStoragePath, sshKeyFileName)

		if err := c.SaveFile(fileHeader, sshKeyPath); err != nil {
			logger.Logger.WithError(err).Error("Failed to save SSH key file")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to save SSH Key file",
			})
		}

		if err := os.Chmod(sshKeyPath, 0600); err != nil {
			logger.Logger.WithError(err).Error("Failed to set permissions on SSH key file")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to set permissions on SSH Key file",
			})
		}
	}

	logDestination := models.LogDestination{
		Type:          req.Type,
		ServerAddress: req.ServerAddress,
		Username:      req.Username,
		Password:      hashedPassword,
		Port:          req.Port,
		SSHKeyPath:    sshKeyPath,
		IPAddress:     req.IPAddress,
		FilePath:      req.FilePath,
	}

	if err := db.DB.Create(&logDestination).Error; err != nil {
		if sshKeyPath != "" {
			_ = os.Remove(sshKeyPath)
		}
		logger.Logger.WithError(err).Error("Failed to create log destination")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to create log destination",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Log destination created successfully",
		Data:    logDestination,
	})
}

func GetAllLogDestinations(c *fiber.Ctx) error {
	var destinations []models.LogDestination
	if err := db.DB.Find(&destinations).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to fetch log destinations")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch log destinations",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Log destinations fetched successfully",
		Data:    destinations,
	})
}

func GetLogDestination(c *fiber.Ctx) error {
	id := c.Params("id")
	destID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid log destination ID",
		})
	}

	var destination models.LogDestination
	if err := db.DB.First(&destination, destID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Log destination not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to fetch log destination")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch log destination",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Log destination fetched successfully",
		Data:    destination,
	})
}

func UpdateLogDestination(c *fiber.Ctx) error {
	id := c.Params("id")
	destID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid log destination ID",
		})
	}

	req := new(requests.UpdateLogDestinationRequest)
	if err := c.BodyParser(req); err != nil {
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

	var destination models.LogDestination
	if err := db.DB.First(&destination, destID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Log destination not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to fetch log destination")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch log destination",
		})
	}

	destination.Type = req.Type
	destination.ServerAddress = req.ServerAddress
	destination.Username = req.Username

	if req.Password != "" {
		hashedPassword, err := cryptology.HashPassword(req.Password)
		if err != nil {
			logger.Logger.WithError(err).Error("Failed to hash password")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "An unexpected error occurred",
			})
		}
		destination.Password = hashedPassword
	}

	destination.Port = req.Port
	destination.IPAddress = req.IPAddress
	destination.FilePath = req.FilePath

	if req.Type == models.SFTP {
		fileHeader, err := c.FormFile("sshKeyFile")
		if err == nil {
			if fileHeader.Size > MaxFileSize {
				return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
					Error:   true,
					Message: fmt.Sprintf("SSH Key file size exceeds %d bytes", MaxFileSize),
				})
			}

			file, err := fileHeader.Open()
			if err != nil {
				logger.Logger.WithError(err).Error("Failed to open uploaded SSH key file")
				return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Failed to process SSH Key file",
				})
			}
			defer file.Close()

			content, err := io.ReadAll(file)
			if err != nil {
				logger.Logger.WithError(err).Error("Failed to read SSH key file content")
				return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Failed to read SSH Key file",
				})
			}

			contentStr := strings.TrimSpace(string(content))
			if !strings.HasPrefix(contentStr, "ssh-") && !strings.HasPrefix(contentStr, "-----BEGIN") {
				return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Invalid SSH Key file format",
				})
			}

			if _, err := file.Seek(0, io.SeekStart); err != nil {
				logger.Logger.WithError(err).Error("Failed to seek SSH key file")
				return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Failed to process SSH Key file",
				})
			}

			if err := os.MkdirAll(SFTPKeyStoragePath, os.ModePerm); err != nil {
				logger.Logger.WithError(err).Error("Failed to create SSH key storage directory")
				return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "An unexpected error occurred",
				})
			}

			sshKeyFileName := fmt.Sprintf("sftp-key-%d.pem", time.Now().UnixNano())
			newSSHKeyPath := filepath.Join(SFTPKeyStoragePath, sshKeyFileName)

			if err := c.SaveFile(fileHeader, newSSHKeyPath); err != nil {
				logger.Logger.WithError(err).Error("Failed to save SSH key file")
				return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Failed to save SSH Key file",
				})
			}

			if err := os.Chmod(newSSHKeyPath, 0600); err != nil {
				logger.Logger.WithError(err).Error("Failed to set permissions on SSH key file")
				return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Failed to set permissions on SSH Key file",
				})
			}

			if destination.SSHKeyPath != "" {
				if err := os.Remove(destination.SSHKeyPath); err != nil && !os.IsNotExist(err) {
					logger.Logger.WithError(err).Error("Failed to remove old SSH key file")
					_ = os.Remove(newSSHKeyPath)
					return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
						Error:   true,
						Message: "Failed to update SSH Key file",
					})
				}
			}

			destination.SSHKeyPath = newSSHKeyPath
		} else {
			if destination.SSHKeyPath == "" {
				return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "SSH Key file is required for SFTP",
				})
			}
		}
	} else {
		if destination.SSHKeyPath != "" {
			if err := os.Remove(destination.SSHKeyPath); err != nil && !os.IsNotExist(err) {
				logger.Logger.WithError(err).Error("Failed to remove existing SSH key file")
				return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
					Error:   true,
					Message: "Failed to update SSH Key file",
				})
			}
			destination.SSHKeyPath = ""
		}
	}

	if err := db.DB.Save(&destination).Error; err != nil {
		if req.Type == models.SFTP && destination.SSHKeyPath != "" {
			_ = os.Remove(destination.SSHKeyPath)
		}
		logger.Logger.WithError(err).Error("Failed to update log destination")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to update log destination",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Log destination updated successfully",
		Data:    destination,
	})
}

func DeleteLogDestination(c *fiber.Ctx) error {
	id := c.Params("id")
	destID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Invalid log destination ID",
		})
	}

	var destination models.LogDestination
	if err := db.DB.First(&destination, destID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.Status(fiber.StatusNotFound).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Log destination not found",
			})
		}
		logger.Logger.WithError(err).Error("Failed to fetch log destination")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to fetch log destination",
		})
	}

	if destination.SSHKeyPath != "" {
		if err := os.Remove(destination.SSHKeyPath); err != nil && !os.IsNotExist(err) {
			logger.Logger.WithError(err).Error("Failed to remove SSH key file")
			return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
				Error:   true,
				Message: "Failed to delete SSH Key file",
			})
		}
	}

	if err := db.DB.Delete(&destination).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to delete log destination")
		return c.Status(fiber.StatusInternalServerError).JSON(responses.ErrorResponse{
			Error:   true,
			Message: "Failed to delete log destination",
		})
	}

	return c.JSON(responses.SuccessResponse{
		Error:   false,
		Message: "Log destination deleted successfully",
	})
}

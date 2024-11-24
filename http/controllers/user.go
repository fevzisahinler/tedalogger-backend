package controllers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
	"strconv"
	"tedalogger-backend/db"
	"tedalogger-backend/http/requests"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
)

func Register(c *fiber.Ctx) error {
	requestUser := new(requests.CreateUserRequest)
	if err := c.BodyParser(requestUser); err != nil {
		logger.Logger.WithError(err).Error("Failed to parse request body")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid input",
		})
	}

	if err := requestUser.Validate(); err != nil {
		logger.Logger.WithError(err).Error("Validation failed")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Invalid input",
		})
	}

	var existingUser models.User
	if err := db.DB.Where("username = ? OR email = ?", requestUser.Username, requestUser.Email).First(&existingUser).Error; err != nil && err != gorm.ErrRecordNotFound {
		logger.Logger.WithError(err).Error("Failed to check existing user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "An unexpected error occurred",
		})
	}

	if existingUser.ID != 0 {
		logger.Logger.Warn("User already exists")
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"message": "User already exists",
		})
	}

	userModel := requestUser.ToModel()
	if err := db.DB.Create(&userModel).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to create user")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "An unexpected error occurred",
		})
	}

	logger.Logger.WithFields(map[string]interface{}{
		"username": userModel.Username,
	}).Info("User created successfully")

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User created successfully",
	})
}

func EditUser(c *fiber.Ctx) error {
	id := c.Params("id")
	userID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Geçersiz kullanıcı ID",
		})
	}

	var updateUserRequest requests.UpdateUserRequest
	if err := c.BodyParser(&updateUserRequest); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "JSON parse edilemedi",
		})
	}

	if err := updateUserRequest.Validate(); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Kullanıcı bulunamadı",
		})
	}

	user.Username = updateUserRequest.Username
	if updateUserRequest.Password != "" {
		user.Password = requests.HashPassword(updateUserRequest.Password)
	}
	user.Name = updateUserRequest.Name
	user.Surname = updateUserRequest.Surname
	user.Email = updateUserRequest.Email
	user.PhoneNumber = updateUserRequest.PhoneNumber

	if err := db.DB.Save(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Kullanıcı güncellenemedi",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Kullanıcı başarıyla güncellendi",
		"data":    user,
	})
}

func DeleteUser(c *fiber.Ctx) error {
	id := c.Params("id")
	userID, err := strconv.Atoi(id)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Geçersiz kullanıcı ID",
		})
	}

	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Kullanıcı bulunamadı",
		})
	}

	if err := db.DB.Delete(&user).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Kullanıcı silinemedi",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Kullanıcı başarıyla silindi",
	})
}

func GetAllUser(c *fiber.Ctx) error {
	var users []models.User
	if err := db.DB.Find(&users).Error; err != nil {
		logger.Logger.WithError(err).Error("Failed to fetch users")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Kullanıcılar getirilemedi",
		})
	}

	return c.JSON(fiber.Map{
		"data": users,
	})
}

func GetUser(c *fiber.Ctx) error {
	id := c.Params("id")
	var user models.User
	if result := db.DB.First(&user, id); result.Error != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	return c.JSON(user)
}

func GetCurrentUser(c *fiber.Ctx) error {
	claims, ok := c.Locals("user").(jwt.MapClaims)
	if !ok {
		logger.Logger.Error("Failed to cast user claims to jwt.MapClaims")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Unauthorized: Invalid token claims",
		})
	}

	idFloat, ok := claims["id"].(float64)
	if !ok {
		logger.Logger.Error("Failed to parse 'id' from token claims")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Invalid token structure",
		})
	}

	userID := uint(idFloat)

	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		logger.Logger.WithError(err).Error("Kullanıcı bulunamadı")
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Kullanıcı bulunamadı",
		})
	}

	logger.Logger.WithField("user", user).Info("User successfully fetched")

	return c.JSON(fiber.Map{
		"message": "Kullanıcı başarıyla getirildi",
		"data":    user,
	})
}

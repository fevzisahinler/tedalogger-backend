package middleware

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/logger"
)

func ErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError

	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	logger.Logger.WithError(err).Error("Unhandled error occurred")

	return c.Status(code).JSON(fiber.Map{
		"error":   true,
		"message": err.Error(),
	})
}

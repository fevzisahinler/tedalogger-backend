package middleware

import (
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"strings"
	"tedalogger-backend/config"
	"tedalogger-backend/logger"
)

func JWTMiddleware() fiber.Handler {
	cfg, err := config.LoadConfig()
	if err != nil {
		panic("Failed to load configuration: " + err.Error())
	}

	secret := cfg.JwtSecretKey
	if secret == "" {
		panic("JWT secret key is missing from configuration")
	}

	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			logger.Logger.Error("Missing authorization header")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Missing authorization header",
			})
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			logger.Logger.Error("Invalid authorization format")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Invalid authorization format, must start with 'Bearer '",
			})
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				logger.Logger.Error("Unexpected signing method")
				return nil, fiber.NewError(fiber.StatusUnauthorized, "Unexpected signing method")
			}
			return []byte(secret), nil
		})

		if err != nil {
			logger.Logger.WithError(err).Error("Invalid or expired token")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Invalid or expired token",
				"error":   err.Error(),
			})
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			logger.Logger.Info("Token successfully parsed", claims)
			c.Locals("user", claims)
		} else {
			logger.Logger.Error("Failed to parse token claims")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Failed to parse token claims",
			})
		}

		return c.Next()
	}
}

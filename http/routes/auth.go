package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
)

func AuthRoutes(app *fiber.App) {
	app.Post("/login", controllers.Login)
}

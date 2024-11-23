package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
)

func UserRoutes(app *fiber.App) {
	app.Post("/register", controllers.Register)
}

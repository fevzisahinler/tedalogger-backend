package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
)

func AuthRoutes(app *fiber.App) {
	app.Post("auth/login", controllers.Login)
	app.Post("auth/register", controllers.Register)

}

package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"
)

func LogDestinationRoutes(app *fiber.App) {

	logDestination := app.Group("log-destinations", middleware.JWTMiddleware())

	logDestination.Post("/create", controllers.CreateLogDestination)
	logDestination.Get("/get-all", controllers.GetAllLogDestinations)
	logDestination.Get("/get/:id", controllers.GetLogDestination)
	logDestination.Put("/update/:id", controllers.UpdateLogDestination)
	logDestination.Delete("/delete/:id", controllers.DeleteLogDestination)
}

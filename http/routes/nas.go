package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"
)

func NASRoutes(app *fiber.App) {
	admin := app.Group("admin", middleware.JWTMiddleware())

	admin.Post("/nas", controllers.CreateNAS)
	admin.Put("/nas/:id", controllers.UpdateNAS)
	admin.Delete("/nas/:id", controllers.DeleteNAS)
	admin.Get("/nas", controllers.GetAllNAS)
}

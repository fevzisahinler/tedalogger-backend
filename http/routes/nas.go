package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"
)

func NASRoutes(app *fiber.App) {
	admin := app.Group("nas", middleware.JWTMiddleware())

	admin.Post("/create", controllers.CreateNAS)
	admin.Put("/update/:id", controllers.UpdateNAS)
	admin.Delete("/delete/:id", controllers.DeleteNAS)
	admin.Get("/get_all", controllers.GetAllNAS)
}

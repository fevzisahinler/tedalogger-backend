package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"
)

func RadiusGroupRoutes(app *fiber.App) {
	radgroup := app.Group("radgroup", middleware.JWTMiddleware())

	radgroup.Post("/create", controllers.CreateRadiusGroup)
	radgroup.Put("/update/:id", controllers.UpdateRadiusGroup)
	radgroup.Delete("/delete/:id", controllers.DeleteRadiusGroup)
	radgroup.Get("/get_all", controllers.GetAllRadiusGroup)
}

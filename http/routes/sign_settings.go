package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"
)

func SignSettingsRoutes(app *fiber.App) {

	signSettings := app.Group("sign-settings", middleware.JWTMiddleware())

	signSettings.Post("/create", controllers.CreateSignSettings)
	signSettings.Get("/get-all", controllers.GetAllSignSettings)
	signSettings.Get("/get/:id", controllers.GetSignSettings)
	signSettings.Put("/update/:id", controllers.UpdateSignSettings)
	signSettings.Delete("/delete/:id", controllers.DeleteSignSettings)
}

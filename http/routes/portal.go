package routes

import (
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"

	"github.com/gofiber/fiber/v2"
)

func PortalRoutes(app *fiber.App) {

	app.Post("/create", controllers.CreatePortal, middleware.JWTMiddleware())
	app.Put("/update/:id", controllers.UpdatePortal, middleware.JWTMiddleware())
	app.Delete("/delete/:id", controllers.DeletePortal, middleware.JWTMiddleware())
	app.Get("/get_all", controllers.GetAllPortals, middleware.JWTMiddleware())
	app.Get("/get_by_id/:id", controllers.GetPortalByID, middleware.JWTMiddleware())
	app.Get("/get_by_uuid/:uuid", controllers.GetPortalByUUID)
}

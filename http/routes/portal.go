package routes

import (
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"

	"github.com/gofiber/fiber/v2"
)

func PortalRoutes(app *fiber.App) {
	portal := app.Group("portal", middleware.JWTMiddleware())

	portal.Post("/create", controllers.CreatePortal)
	portal.Put("/update/:id", controllers.UpdatePortal)
	portal.Delete("/delete/:id", controllers.DeletePortal)
	portal.Get("/get_all", controllers.GetAllPortals)
	portal.Get("/get_by_id/:id", controllers.GetPortalByID)
	portal.Get("/get_by_uuid/:uuid", controllers.GetPortalByUUID)
}

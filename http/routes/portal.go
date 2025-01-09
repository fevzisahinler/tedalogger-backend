// routes/portal.go

package routes

import (
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"

	"github.com/gofiber/fiber/v2"
)

func PortalRoutes(app *fiber.App) {

	app.Post("/portal/create", controllers.CreatePortal, middleware.JWTMiddleware())
	app.Put("/portal/update/:id", controllers.UpdatePortal, middleware.JWTMiddleware())
	app.Delete("/portal/delete/:id", controllers.DeletePortal, middleware.JWTMiddleware())
	app.Get("/portal/get_all", controllers.GetAllPortals, middleware.JWTMiddleware())
	app.Get("/portal/get_by_id/:id", controllers.GetPortalByID, middleware.JWTMiddleware())
	app.Get("/portal/get_by_uuid/:uuid", controllers.GetPortalByUUID)
}

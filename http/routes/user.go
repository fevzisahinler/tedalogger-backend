package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"
)

func UserRoutes(app *fiber.App) {

	app.Get("users/get_all", middleware.JWTMiddleware(), controllers.GetAllUser)
	app.Get("users/me", middleware.JWTMiddleware(), controllers.GetCurrentUser)

	app.Put("users/:id/edit", middleware.JWTMiddleware(), controllers.EditUser)
	app.Delete("users/:id/delete", middleware.JWTMiddleware(), controllers.DeleteUser)

	app.Get("users/:id", middleware.JWTMiddleware(), controllers.GetUser)

}

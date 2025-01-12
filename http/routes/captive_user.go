// routes/captive_user.go

package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"
)

func CaptiveUserRoutes(app *fiber.App) {

	app.Post("/captive_user/create", middleware.JWTMiddleware(), controllers.CreateCaptiveUser)
	app.Get("/captive_user/get/:id", middleware.JWTMiddleware(), controllers.GetCaptiveUser)
	app.Put("/captive_user/update/:id", middleware.JWTMiddleware(), controllers.UpdateCaptiveUser)
	app.Delete("/captive_user/delete/:id", middleware.JWTMiddleware(), controllers.DeleteCaptiveUser)
	app.Get("/captive_user/get-all", middleware.JWTMiddleware(), controllers.GetAllCaptiveUsers)

	app.Post("/captive_user/register", controllers.RegisterCaptiveUser)
	app.Post("/captive_user/verify_otp", controllers.VerifyOTP)
	app.Post("/captive_user/login", controllers.LoginCaptiveUser)
	app.Post("/captive_user/verify_login_otp", controllers.VerifyLoginOTP)
	app.Post("/captive_user/resend_otp", controllers.ResendOTP)
}

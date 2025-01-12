// routes/captive_user.go

package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
	"tedalogger-backend/http/middleware"
)

func CaptiveUserRoutes(app *fiber.App) {
	protected := app.Group("/captive_user", middleware.JWTMiddleware())

	protected.Post("/create", controllers.CreateCaptiveUser)
	protected.Get("/get/:id", controllers.GetCaptiveUser)
	protected.Put("/update/:id", controllers.UpdateCaptiveUser)
	protected.Delete("/delete/:id", controllers.DeleteCaptiveUser)
	protected.Get("/get-all", controllers.GetAllCaptiveUsers)

	captiveUser := app.Group("/captive_user")

	captiveUser.Post("/register", controllers.RegisterCaptiveUser)
	captiveUser.Post("/verify_otp", controllers.VerifyOTP)
	captiveUser.Post("/login", controllers.LoginCaptiveUser)
	captiveUser.Post("verify_login_otp", controllers.VerifyLoginOTP)
	captiveUser.Post("/resend_otp", controllers.ResendOTP)
}

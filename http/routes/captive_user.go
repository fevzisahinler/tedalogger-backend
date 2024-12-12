// routes/captive_user.go

package routes

import (
	"github.com/gofiber/fiber/v2"
	"tedalogger-backend/http/controllers"
)

func CaptiveUserRoutes(app *fiber.App) {
	captiveUser := app.Group("/captive_user")

	captiveUser.Post("/register", controllers.RegisterCaptiveUser)
	captiveUser.Post("/verify_otp", controllers.VerifyOTP)
	captiveUser.Post("/login", controllers.LoginCaptiveUser)
	captiveUser.Post("verify_login_otp", controllers.VerifyLoginOTP)
}

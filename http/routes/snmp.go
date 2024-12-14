package routes

import (
    "github.com/gofiber/fiber/v2"
    "tedalogger-backend/http/controllers"
)

func SnmpRoutes(app *fiber.App) {
    snmpGroup := app.Group("/snmp")
    snmpGroup.Post("/stats", controllers.GetSnmpStats)
}

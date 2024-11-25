package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	fiberLogger "github.com/gofiber/fiber/v2/middleware/logger"
	apmfiber "go.elastic.co/apm/module/apmfiber/v2"

	"tedalogger-backend/config"
	"tedalogger-backend/db"
	"tedalogger-backend/http/middleware"
	"tedalogger-backend/http/routes"
	"tedalogger-backend/logger"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if err := logger.InitLogger(); err != nil {
		log.Fatalf("Could not initialize logger: %v", err)
	}
	defer func() {
		if f, ok := logger.Logger.Out.(*os.File); ok {
			f.Close()
		}
	}()

	os.Setenv("ELASTIC_APM_SERVER_URL", cfg.ElasticAPMServerURL)
	os.Setenv("ELASTIC_APM_SERVICE_NAME", cfg.ElasticAPMServiceName)
	os.Setenv("ELASTIC_APM_ENVIRONMENT", cfg.ElasticAPMEnvironment)

	app := fiber.New(fiber.Config{
		ErrorHandler: middleware.ErrorHandler,
	})

	app.Use(cors.New())

	app.Use(apmfiber.Middleware())

	app.Use(fiberLogger.New(fiberLogger.Config{
		Format:     "${ip} - - [${time}] \"${method} ${path} ${protocol}\" ${status} ${latency}\n",
		TimeFormat: "02/Jan/2024:15:04:05 -0700",
	}))

	if err := db.ConnectDatabase(cfg); err != nil {
		logger.Logger.WithError(err).Fatal("Database connection failed")
	}

	routes.UserRoutes(app)
	routes.AuthRoutes(app)

	port := ":4000"
	logger.Logger.Infof("Server is running on port %s", port)
	go func() {
		if err := app.Listen(port); err != nil {
			logger.Logger.WithError(err).Fatal("Server failed to start")
		}
	}()

	waitForShutdown()
}

func waitForShutdown() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	logger.Logger.Info("Shutting down server...")
}

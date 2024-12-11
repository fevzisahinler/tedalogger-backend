package db

import (
	"fmt"
	"time"

	apmgormv2 "go.elastic.co/apm/module/apmgormv2/v2/driver/postgres"
	"gorm.io/gorm"

	"tedalogger-backend/config"
	"tedalogger-backend/logger"
	"tedalogger-backend/models"
)

var DB *gorm.DB

func ConnectDatabase(cfg *config.Config) error {
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable password=%s port=%s",
		cfg.PGHost,
		cfg.PGUser,
		cfg.PGDBName,
		cfg.PGPassword,
		cfg.PGPort,
	)

	database, err := gorm.Open(apmgormv2.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to connect to database")
		return err
	}

	sqlDB, err := database.DB()
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to get database instance")
		return err
	}
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	if err := AutoMigrate(database); err != nil {
		return err
	}

	logger.Logger.Info("Database connected successfully")
	DB = database
	return nil
}

func AutoMigrate(database *gorm.DB) error {
	if err := database.AutoMigrate(&models.User{}, &models.Role{}, &models.Resource{}, &models.Permission{}, &models.NAS{}, &models.RadGroup{}, &models.Portal{}, &models.LogDestination{}, &models.SignSettings{}, &models.CaptiveUser{}); err != nil {
		logger.Logger.WithError(err).Error("Failed to migrate models")
		return err
	}
	return nil
}

package db

import (
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"tedalogger-backend/config"
	"tedalogger-backend/logger"
)

var RadiusDB *gorm.DB

func ConnectRadiusDB(cfg *config.Config) error {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.RadiusDBUser,
		cfg.RadiusDBPassword,
		cfg.RadiusDBHost,
		cfg.RadiusDBPort,
		cfg.RadiusDBName,
	)

	database, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to connect to Radius MySQL DB")
		return err
	}

	sqlDB, err := database.DB()
	if err != nil {
		logger.Logger.WithError(err).Error("Failed to get Radius DB instance")
		return err
	}
	sqlDB.SetConnMaxLifetime(time.Hour)

	RadiusDB = database
	logger.Logger.Info("Radius MySQL connected successfully")
	return nil
}

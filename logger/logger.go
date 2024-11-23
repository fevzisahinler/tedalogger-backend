package logger

import (
	"github.com/sirupsen/logrus"
	"os"
)

var Logger *logrus.Logger

func InitLogger() error {
	Logger = logrus.New()
	Logger.SetOutput(os.Stdout)
	Logger.SetFormatter(&logrus.TextFormatter{
		DisableColors:   true,
		TimestampFormat: "02/Jan/2006:15:04:05 -0700",
		FullTimestamp:   true,
	})
	Logger.SetLevel(logrus.InfoLevel)
	return nil
}

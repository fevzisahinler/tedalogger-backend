package config

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	PGHost                string
	PGUser                string
	PGDBName              string
	PGPassword            string
	PGPort                string
	JwtSecretKey          string
	ServiceName           string
	ElasticAPMServerURL   string
	ElasticAPMServiceName string
	ElasticAPMEnvironment string

	RadiusDBHost     string
	RadiusDBUser     string
	RadiusDBPassword string
	RadiusDBName     string
	RadiusDBPort     string

	RADIUSServerIP     string
	RADIUSServerPort   string
	RADIUSSharedSecret string

	OTPSendUser          string
	OTPSendPassword      string
	PostaGuverciniSMSURL string
	OTPExpireSeconds     int

	LOGO_STORAGE       string
	BACKGROUND_STORAGE string
}

func LoadConfig() (*Config, error) {
	_ = godotenv.Load()

	config := &Config{
		PGHost:                os.Getenv("PG_HOST"),
		PGUser:                os.Getenv("PG_USER"),
		PGDBName:              os.Getenv("PG_DBNAME"),
		PGPassword:            os.Getenv("PG_PASSWORD"),
		PGPort:                os.Getenv("PG_PORT"),
		JwtSecretKey:          os.Getenv("JwtSecretKey"),
		ServiceName:           os.Getenv("SERVICE_NAME"),
		ElasticAPMServerURL:   os.Getenv("ELASTIC_APM_SERVER_URL"),
		ElasticAPMServiceName: os.Getenv("ELASTIC_APM_SERVICE_NAME"),
		ElasticAPMEnvironment: os.Getenv("ELASTIC_APM_ENVIRONMENT"),

		RadiusDBHost:     os.Getenv("RADIUS_DB_HOST"),
		RadiusDBUser:     os.Getenv("RADIUS_DB_USER"),
		RadiusDBPassword: os.Getenv("RADIUS_DB_PASSWORD"),
		RadiusDBName:     os.Getenv("RADIUS_DB_NAME"),
		RadiusDBPort:     os.Getenv("RADIUS_DB_PORT"),

		RADIUSServerIP:     os.Getenv("RADIUS_SERVER_IP"),
		RADIUSServerPort:   os.Getenv("RADIUS_SERVER_PORT"),
		RADIUSSharedSecret: os.Getenv("RADIUS_SHARED_SECRET"),

		OTPSendUser:          os.Getenv("OTP_SEND_USER"),
		OTPSendPassword:      os.Getenv("OTP_SEND_PASSWORD"),
		PostaGuverciniSMSURL: os.Getenv("POSTAGUVERCINI_SMS_URL"),
		BACKGROUND_STORAGE:   os.Getenv("BACKGROUND_STORAGE"),
		LOGO_STORAGE:         os.Getenv("LOGO_STORAGE"),
	}

	if val, err := strconv.Atoi(os.Getenv("OTP_EXPIRE_SECONDS")); err == nil {
		config.OTPExpireSeconds = val
	} else {
		config.OTPExpireSeconds = 20
	}

	return config, nil
}

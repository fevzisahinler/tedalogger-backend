package config

import (
	"os"

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
}

func LoadConfig() (*Config, error) {
	if err := godotenv.Load(); err != nil {
	}

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
	}

	return config, nil
}

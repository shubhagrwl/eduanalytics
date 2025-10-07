package config

import (

	// if using go modules

	"github.com/caarlos0/env/v6"
	"github.com/joho/godotenv"
)

type JwtConfig struct {
	JWT_MAGIC_SECRET   string `env:"JWT_MAGIC_SECRET"`
	JWT_ACCESS_SECRET  string `env:"JWT_ACCESS_SECRET"`
	JWT_REFRESH_SECRET string `env:"JWT_REFRESH_SECRET"`
	JWT_ACCESS_EXP     int    `env:"JWT_ACCESS_EXP"`
	JWT_REFRESH_EXP    int    `env:"JWT_REFRESH_EXP"`
}

type DatabaseConfig struct {
	DB_HOST                    string `env:"DB_HOST"`
	DB_PORT                    string `env:"DB_PORT"`
	DB_USER                    string `env:"DB_USER"`
	DB_NAME                    string `env:"DB_NAME"`
	DB_PASSWORD                string `env:"DB_PASSWORD"`
	DB_MAX_OPEN_CONNECTION     int    `env:"DB_MAX_OPEN_CONNECTION"`
	DB_MAX_IDLE_CONNECTION     int    `env:"DB_MAX_IDLE_CONNECTION"`
	DB_CONNECTION_MAX_LIFETIME int    `env:"DB_CONNECTION_MAX_LIFETIME"`
	DB_LOG_MODE                bool   `env:"DB_LOGMODE"`
	DB_SCHEMA                  string `env:"DB_SCHEMA"`
}

type HTTPServerConfig struct {
	HTTPSERVER_URL                         string `env:"HTTPSERVER_URL"`
	HTTPSERVER_LISTEN                      string `env:"HTTPSERVER_LISTEN"`
	HTTPSERVER_PORT                        string `env:"HTTPSERVER_PORT"`
	HTTPSERVER_READ_TIMEOUT                int    `env:"HTTPSERVER_READ_TIMEOUT"`
	HTTPSERVER_WRITE_TIMEOUT               int    `env:"HTTPSERVER_WRITE_TIMEOUT"`
	HTTPSERVER_MAX_CONNECTIONS_PER_IP      int    `env:"HTTPSERVER_MAX_CONNECTIONS_PER_IP"`
	HTTPSERVER_MAX_REQUESTS_PER_CONNECTION int    `env:"HTTPSERVER_MAX_REQUESTS_PER_CONNECTION"`
	HTTPSERVER_MAX_KEEP_ALIVE_DURATION     int    `env:"HTTPSERVER_MAX_KEEP_ALIVE_DURATION"`
}

type LogConfig struct {
	LOG_FILE_PATH      string `env:"LOG_FILE_PATH"`
	LOG_FILE_NAME      string `env:"LOG_FILE_NAME"`
	LOG_FILE_MAXSIZE   int    `env:"LOG_FILE_MAXSIZE"`
	LOG_FILE_MAXBACKUP int    `env:"LOG_FILE_MAXBACKUP"`
	LOG_FILE_MAXAGE    int    `env:"LOG_FILE_MAXAGE"`
}

type ServiceConfig struct {
	ProjectVersion   string `env:"VERSION"`
	JwtConfig        JwtConfig
	DatabaseConfig   DatabaseConfig
	HTTPServerConfig HTTPServerConfig
	LogConfig        LogConfig
	Environment      string `env:"ENVIRONMENT"`
}

var Config *ServiceConfig

func LoadConfig() (*ServiceConfig, error) {
	err := godotenv.Load(".env") // Load environment variables from .env file
	if err != nil {
		panic("Error loading .env file " + err.Error()) // Panic if .env file cannot be loaded
	}

	config := ServiceConfig{} // Create a variable to hold the configuration
	if err := env.Parse(&config); err != nil {
		panic("unable to load env config " + err.Error()) // Panic if environment variables cannot be parsed
	}

	return &config, nil // Return the loaded configuration
}

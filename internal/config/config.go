package config

import (
	"context"
	"fmt"

	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

type Config struct {
	DB      DatabaseConfig `envconfig:"DB"`
	Logging LoggingConfig  `envconfig:"LOG"`
	Server  ServerConfig   `envconfig:"SERVER"`
	Auth    AuthConfig     `envconfig:"AUTH"`
}

type DatabaseConfig struct {
	DSN string `envconfig:"DSN" required:"true"`
}

type LoggingConfig struct {
	Level string `envconfig:"LEVEL" default:"debug"`
}

type ServerConfig struct {
	Port string `envconfig:"PORT" default:"8080"`
}

type AuthConfig struct {
	URL       string `envconfig:"URL" required:"true"`
	APIKey    string `envconfig:"API_KEY" required:"true"`
	JWTSecret string `envconfig:"JWT_SECRET" required:"true"`
}

func Init(ctx context.Context) *Config {
	cfg, err := loadConfig(ctx)
	if err != nil {
		panic(err)
	}

	return cfg
}

func loadConfig(ctx context.Context) (*Config, error) {
	if ctx == nil {
		panic("context must not be nil")
	}

	if err := godotenv.Load(); err != nil {
		logrus.Warn("No .env file found, using environment variables")
	}

	var cfg Config

	if err := envconfig.Process("", &cfg); err != nil {
		return nil, fmt.Errorf("failed to process config: %w", err)
	}

	return &cfg, nil
}

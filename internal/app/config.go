package app

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config contains global runtime configuration.
type Config struct {
	Workspace string
	LogLevel  string
	Timeout   time.Duration
}

// MustLoadConfigFromViper builds Config from Viper-bound flags/env.
func MustLoadConfigFromViper() Config {
	ws := viper.GetString("workspace")
	if ws == "" {
		panic("workspace is empty")
	}
	return Config{
		Workspace: ws,
		LogLevel:  viper.GetString("log_level"),
		Timeout:   viper.GetDuration("timeout"),
	}
}

// Validate returns error if configuration is invalid.
func (c Config) Validate() error {
	if c.Workspace == "" {
		return fmt.Errorf("workspace cannot be empty")
	}
	return nil
}

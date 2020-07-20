package config

import (
	"fmt"

	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
)

type AppConfig struct {
	Port   string
	AppKey string
	Db     *gorm.DB
	DbErr  error
	DbDsn  string `mapstructure:"dbdsn"`
}

var Config AppConfig

func LoadConfig(configPaths ...string) error {
	v := viper.New()
	v.SetConfigName("env")
	v.SetConfigType("yaml")
	v.SetEnvPrefix("ImageServe")
	v.AutomaticEnv()

	for _, path := range configPaths {
		v.AddConfigPath(path)
	}

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("Failed to read the configuration file: %s", err)
	}

	return v.Unmarshal(&Config)
}

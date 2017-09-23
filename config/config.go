package config

import (
	"flag"
	"os"

	"github.com/juju/errors"
	"github.com/naoina/toml"
	log "github.com/sirupsen/logrus"
)

var (
	configPath = flag.String("config", "/etc/redsys-nosni-proxy/config.toml", "Configuration file")
)

type Config struct {
	ACMEEmail            string `toml:"acme-email"`
	GoogleServiceAccount string `toml:"google-service-account"`
	NotificationURL      string `toml:"notification-url"`
	Hostname             string `toml:"hostname"`
}

func Load() (*Config, error) {
	log.WithFields(log.Fields{"path": *configPath}).Info("load config file")

	f, err := os.Open(*configPath)
	if err != nil {
		return nil, errors.Trace(err)
	}
	defer f.Close()

	cnf := new(Config)
	if err := toml.NewDecoder(f).Decode(cnf); err != nil {
		return nil, errors.Trace(err)
	}

	return cnf, nil
}

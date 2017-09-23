package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"time"

	"github.com/juju/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"proxy/config"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(errors.ErrorStack(err))
	}
}

func run() error {
	flag.Parse()

	if config.IsDebug() {
		log.SetFormatter(&log.TextFormatter{
			ForceColors:   true,
			FullTimestamp: true,
		})
	}

	cnf, err := config.Load()
	if err != nil {
		return errors.Trace(err)
	}

	cache, err := NewDatastoreCache(cnf)
	if err != nil {
		return errors.Trace(err)
	}
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(cnf.Hostname),
		Email:      cnf.ACMEEmail,
		Cache:      cache,
	}
	if config.IsDebug() {
		manager.Client = &acme.Client{
			DirectoryURL: "https://acme-staging.api.letsencrypt.org/directory",
		}
	}

	go func() {
		log.WithFields(log.Fields{"address": "localhost:9080"}).Info("run insecure server")
		server := &http.Server{
			Addr:         ":9080",
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			Handler:      http.HandlerFunc(InsecureHandler),
		}
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(errors.ErrorStack(err))
		}
	}()

	log.WithFields(log.Fields{
		"address":    "localhost:9443",
		"acme-email": cnf.ACMEEmail,
		"hostname":   cnf.Hostname,
	}).Info("run secure server")

	server := &http.Server{
		Addr:         ":9443",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      SecureHandler(cnf),
		TLSConfig: &tls.Config{
			GetCertificate: clientHello(cnf, manager),
		},
	}
	if err := server.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
		return errors.Trace(err)
	}

	return nil
}

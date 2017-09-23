package main

import (
	"context"
	"crypto/tls"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/datastore"
	"github.com/juju/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"

	"proxy/config"
)

const (
	KindCache = "Cache"
	Namespace = "redsys-nosni-proxy"
)

type CacheModel struct {
	Data []byte `datastore:",noindex"`
}

func (model *CacheModel) Key(key string) *datastore.Key {
	return &datastore.Key{
		Kind:      KindCache,
		Name:      key,
		Namespace: Namespace,
	}
}

type DatastoreCache struct {
	client *datastore.Client
}

func NewDatastoreCache(cnf *config.Config) (*DatastoreCache, error) {
	project := "test-project"
	if !config.IsDebug() {
		var err error
		project, err = metadata.ProjectID()
		if err != nil {
			return nil, errors.Trace(err)
		}
	}

	jwtconfig, err := google.JWTConfigFromJSON([]byte(cnf.GoogleServiceAccount), datastore.ScopeDatastore)
	if err != nil {
		return nil, errors.Trace(err)
	}
	ctx := context.Background()
	client, err := datastore.NewClient(ctx, project, option.WithTokenSource(jwtconfig.TokenSource(ctx)))
	if err != nil {
		return nil, errors.Trace(err)
	}

	return &DatastoreCache{client}, nil
}

func (cache *DatastoreCache) Get(ctx context.Context, key string) ([]byte, error) {
	log.WithFields(log.Fields{"key": key}).Info("get autocert cache key")

	model := new(CacheModel)
	if err := cache.client.Get(ctx, model.Key(key), model); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return nil, autocert.ErrCacheMiss
		}

		log.WithFields(log.Fields{"error": err}).Error("cannot get acme cache")
		return nil, errors.Trace(err)
	}

	return model.Data, nil
}

func (cache *DatastoreCache) Put(ctx context.Context, key string, data []byte) error {
	log.WithFields(log.Fields{"key": key}).Info("put autocert cache key")

	model := &CacheModel{
		Data: data,
	}
	if _, err := cache.client.Put(ctx, model.Key(key), model); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("cannot put acme cache")
		return errors.Trace(err)
	}

	return nil
}

func (cache *DatastoreCache) Delete(ctx context.Context, key string) error {
	log.WithFields(log.Fields{"key": key}).Info("delete autocert cache key")

	model := new(CacheModel)
	if err := cache.client.Delete(ctx, model.Key(key)); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("cannot delete acme cache")
		return errors.Trace(err)
	}

	return nil
}

func clientHello(cnf *config.Config, manager *autocert.Manager) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != "" && hello.ServerName != cnf.Hostname {
			return manager.GetCertificate(hello)
		}
		
		hello.ServerName = cnf.Hostname
		return manager.GetCertificate(hello)
	}
}

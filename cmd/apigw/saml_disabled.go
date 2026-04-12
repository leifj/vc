//go:build !saml

package main

import (
	"context"
	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/internal/apigw/httpserver"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

func initSAMLSPService(ctx context.Context, cfg *model.Cfg, _ *cache.Service, log *logger.Log) (httpserver.SAMLSPService, error) {
	if cfg.APIGW.SAML.Enable {
		log.Info("SAML enabled in config but not compiled in. Rebuild with -tags saml")
	}
	return nil, nil
}

//go:build !saml

package main

import (
	"context"
	"vc/internal/issuer/httpserver"
	"vc/pkg/logger"
	"vc/pkg/model"
)

func initSAMLService(ctx context.Context, cfg *model.Cfg, log *logger.Log) (httpserver.SAMLService, error) {
	if cfg.Issuer.SAML.Enabled {
		log.Info("SAML enabled in config but not compiled in. Rebuild with -tags saml")
	}
	return nil, nil
}

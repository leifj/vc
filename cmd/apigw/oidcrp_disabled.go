//go:build !oidcrp

package main

import (
	"context"
	"github.com/SUNET/vc/internal/apigw/cache"
	"github.com/SUNET/vc/internal/apigw/db"
	"github.com/SUNET/vc/internal/apigw/httpserver"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
)

func initOIDCRPService(ctx context.Context, cfg *model.Cfg, _ *cache.Service, dbService *db.Service, log *logger.Log) (httpserver.OIDCRPService, error) {
	if cfg.APIGW.OIDCRP.Enable {
		log.Info("OIDC RP enabled in config but not compiled in. Rebuild with -tags oidcrp")
	}
	return nil, nil
}

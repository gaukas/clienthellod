package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gaukas/clienthellod/modcaddy/app"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("clienthellod", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		m := &Handler{}
		// err := m.UnmarshalCaddyfile(h.Dispenser)
		return m, nil
	})
}

type Handler struct {
	logger    *zap.Logger
	reservoir *app.Reservoir
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.clienthellod",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	if !ctx.AppIsConfigured(app.CaddyAppID) {
		return errors.New("handler: clienthellod is not configured")
	}
	a, err := ctx.App(app.CaddyAppID)
	if err != nil {
		return err
	}
	h.reservoir = a.(*app.Reservoir)
	h.logger.Info("clienthellod handler provisioned!")
	return nil
}

func (h *Handler) ServeHTTP(wr http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error {
	// get the client hello from the reservoir
	ch := h.reservoir.WithdrawClientHello(req.RemoteAddr)
	if ch == nil {
		h.logger.Debug(fmt.Sprintf("Can't withdraw client hello from %s, is it not a TLS connection?", req.RemoteAddr))
		return next.ServeHTTP(wr, req)
	}
	h.logger.Debug(fmt.Sprintf("Withdrew client hello from %s", req.RemoteAddr))

	err := ch.ParseClientHello()
	if err != nil {
		h.logger.Error("failed to parse client hello", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}

	h.logger.Debug("ClientHello ID: " + ch.FingerprintID(false))
	h.logger.Debug("ClientHello NormID: " + ch.FingerprintID(true))

	// dump JSON
	var b []byte
	if req.URL.Query().Get("beautify") == "true" {
		b, err = json.MarshalIndent(ch, "", "  ")
	} else {
		b, err = json.Marshal(ch)
	}
	if err != nil {
		h.logger.Error("failed to marshal client hello", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}

	// write JSON to response
	h.logger.Debug("ClientHello: " + string(b))
	wr.Header().Set("Content-Type", "application/json")
	wr.Header().Set("Connection", "close")
	_, err = wr.Write(b)
	if err != nil {
		h.logger.Error("failed to write response", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	// _ caddyfile.Unmarshaler       = (*Handler)(nil)
)

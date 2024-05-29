package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/gaukas/clienthellod/modcaddy/app"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("clienthellod", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		m := &Handler{}
		return m, m.UnmarshalCaddyfile(h.Dispenser)
	})
}

type Handler struct {
	// TLS enables handler to look up TLS ClientHello from reservoir.
	//
	// Mutually exclusive with QUIC. One and only one of TLS or QUIC must be true.
	TLS bool `json:"tls,omitempty"`

	// QUIC enables handler to look up QUIC ClientHello from reservoir.
	//
	// Mutually exclusive with TLS. One and only one of TLS or QUIC must be true.
	QUIC bool `json:"quic,omitempty"`

	logger    *zap.Logger
	reservoir *app.Reservoir
}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo { // skipcq: GO-W1029
	return caddy.ModuleInfo{
		ID:  "http.handlers.clienthellod",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision implements caddy.Provisioner.
func (h *Handler) Provision(ctx caddy.Context) error { // skipcq: GO-W1029
	h.logger = ctx.Logger(h)
	h.logger.Info("clienthellod handler logger loaded.")

	if a := ctx.AppIfConfigured(app.CaddyAppID); a == nil {
		return errors.New("clienthellod handler: global reservoir is not configured")
	} else {
		h.reservoir = a.(*app.Reservoir)
		h.logger.Info("clienthellod handler reservoir loaded.")
	}

	if h.TLS && h.QUIC {
		return errors.New("clienthellod handler: mutually exclusive TLS and QUIC are both enabled")
	} else if !(h.TLS || h.QUIC) {
		return errors.New("clienthellod handler: one and only one of TLS or QUIC must be enabled")
	}

	h.logger.Info("clienthellod handler provisioned.")

	return nil
}

func (h *Handler) ServeHTTP(wr http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error { // skipcq: GO-W1029
	h.logger.Debug("Sering HTTP to " + req.RemoteAddr + " on Protocol " + req.Proto)

	if h.TLS && req.ProtoMajor <= 2 { // HTTP/1.0, HTTP/1.1, H2
		return h.serveHTTP12(wr, req, next) // TLS ClientHello capture enabled, serve ClientHello
	} else if h.QUIC && req.ProtoMajor == 3 { // QUIC
		return h.serveQUIC(wr, req, next)
	}
	return next.ServeHTTP(wr, req)
}

// serveHTTP12 handles HTTP/1.0, HTTP/1.1, H2 requests by looking up the
// ClientHello from the reservoir and writing it to the response.
func (h *Handler) serveHTTP12(wr http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error { // skipcq: GO-W1029
	// get the client hello from the reservoir
	ch := h.reservoir.TLSFingerprinter().Lookup(req.RemoteAddr)
	if ch == nil {
		h.logger.Debug(fmt.Sprintf("Can't extract TLS ClientHello sent by %s, maybe not TLS connection?", req.RemoteAddr))
		return next.ServeHTTP(wr, req)
	}
	h.logger.Debug(fmt.Sprintf("Extracted TLS ClientHello for %s", req.RemoteAddr))

	// err := ch.ParseClientHello()
	// if err != nil {
	// 	h.logger.Error("failed to parse client hello", zap.Error(err))
	// 	return next.ServeHTTP(wr, req)
	// }

	h.logger.Debug("ClientHello ID: " + ch.HexID)
	h.logger.Debug("ClientHello NormID: " + ch.NormHexID)
	h.logger.Debug("User-Agent: " + req.UserAgent())
	ch.UserAgent = req.UserAgent()

	// dump JSON
	var b []byte
	var err error
	if req.URL.Query().Get("beautify") == "true" {
		b, err = json.MarshalIndent(ch, "", "  ")
	} else {
		b, err = json.Marshal(ch)
	}
	if err != nil {
		h.logger.Error("failed to marshal TLS ClientHello into JSON", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}

	// write JSON to response
	h.logger.Debug("ClientHello: " + string(b))
	wr.Header().Set("Content-Type", "application/json")
	wr.Header().Set("Connection", "close")
	wr.Header().Set("Alt-Svc", "clear") // to invalidate QUIC
	_, err = wr.Write(b)
	if err != nil {
		h.logger.Error("failed to write response", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}
	return nil
}

// serveQUIC handles QUIC requests by looking up the ClientHello from the
// reservoir and writing it to the response.
func (h *Handler) serveQUIC(wr http.ResponseWriter, req *http.Request, next caddyhttp.Handler) error { // skipcq: GO-W1029
	// get the client hello from the reservoir
	qfp, err := h.reservoir.QUICFingerprinter().LookupAwait(req.RemoteAddr)
	if err != nil {
		h.logger.Error(fmt.Sprintf("Can't extract QUIC fingerprint sent by %s: %v", req.RemoteAddr, err))
		return next.ServeHTTP(wr, req)
	}

	h.logger.Debug(fmt.Sprintf("Extracted QUIC fingerprint for %s", req.RemoteAddr))

	qfp.UserAgent = req.UserAgent()

	// dump JSON
	var b []byte
	if req.URL.Query().Get("beautify") == "true" {
		b, err = json.MarshalIndent(qfp, "", "  ")
	} else {
		b, err = json.Marshal(qfp)
	}
	if err != nil {
		h.logger.Error("failed to marshal QUIC fingerprint into JSON", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}

	// write JSON to response
	wr.Header().Set("Content-Type", "application/json")
	wr.Header().Set("Connection", "close")
	_, err = wr.Write(b)
	if err != nil {
		h.logger.Error("failed to write response", zap.Error(err))
		return next.ServeHTTP(wr, req)
	}
	return nil
}

// UnmarshalCaddyfile unmarshals Caddyfile tokens into h.
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { // skipcq: GO-W1029
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "tls":
				if h.TLS {
					return d.Err("clienthellod: repeated tls in block")
				} else if h.QUIC {
					return d.Err("clienthellod: tls and quic are mutually exclusive in one block")
				}
				h.TLS = true
			case "quic":
				if h.QUIC {
					return d.Err("clienthellod: repeated quic in block")
				} else if h.TLS {
					return d.Err("clienthellod: tls and quic are mutually exclusive in one block")
				}
				h.QUIC = true
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
	_ caddyfile.Unmarshaler       = (*Handler)(nil)
)

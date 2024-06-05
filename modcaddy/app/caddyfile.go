package app

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption(CaddyAppID, parseCaddyfile)
}

/*
Caddyfile syntax:

	trojan {
		validfor 5s [2s]
	}

The second argument is an optional cleaning interval, if left out, it will be the same
as the first argument (validfor).
*/
func parseCaddyfile(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := &Reservoir{
		TlsTTL:  caddy.Duration(DEFAULT_TLS_FP_TTL),
		QuicTTL: caddy.Duration(DEFAULT_QUIC_FP_TTL),
	}

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() { // skipcq: CRT-A0014
			case "tls_ttl": // Time-to-Live for each entry
				if app.TlsTTL != caddy.Duration(DEFAULT_TLS_FP_TTL) {
					return nil, d.Err("only one tls_ttl is allowed")
				}
				args := d.RemainingArgs()
				if len(args) == 0 {
					return nil, d.ArgErr()
				}
				duration, err := caddy.ParseDuration(args[0])
				if err != nil {
					return nil, d.Errf("invalid duration: %v", err)
				}
				app.TlsTTL = caddy.Duration(duration)

				if len(args) > 1 {
					return nil, d.Err("too many arguments")
				}
			case "quic_ttl": // Time-to-Live for each entry
				if app.QuicTTL != caddy.Duration(DEFAULT_QUIC_FP_TTL) {
					return nil, d.Err("only one quic_ttl is allowed")
				}
				args := d.RemainingArgs()
				if len(args) == 0 {
					return nil, d.ArgErr()
				}
				duration, err := caddy.ParseDuration(args[0])
				if err != nil {
					return nil, d.Errf("invalid duration: %v", err)
				}
				app.QuicTTL = caddy.Duration(duration)

				if len(args) > 1 {
					return nil, d.Err("too many arguments")
				}
			}
		}
	}

	return httpcaddyfile.App{
		Name:  CaddyAppID,
		Value: caddyconfig.JSON(app, nil),
	}, nil
}

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
		ValidFor:      caddy.Duration(DEFAULT_RESERVOIR_ENTRY_VALID_FOR),
		CleanInterval: caddy.Duration(DEFAULT_RESERVOIR_CLEANING_INTERVAL),
	}

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() { // skipcq: CRT-A0014
			case "validfor":
				if app.ValidFor != caddy.Duration(DEFAULT_RESERVOIR_ENTRY_VALID_FOR) {
					return nil, d.Err("only one valid is allowed")
				}
				args := d.RemainingArgs()
				if len(args) == 0 {
					return nil, d.ArgErr()
				}
				duration, err := caddy.ParseDuration(args[0])
				if err != nil {
					return nil, d.Errf("invalid duration: %v", err)
				}
				app.ValidFor = caddy.Duration(duration)
				app.CleanInterval = caddy.Duration(duration)
				// second argument is optional (clean interval)
				if len(args) == 2 {
					duration, err := caddy.ParseDuration(args[1])
					if err != nil {
						return nil, d.Errf("invalid duration: %v", err)
					}
					app.CleanInterval = caddy.Duration(duration)
				}
				if len(args) > 2 {
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

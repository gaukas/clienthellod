package app

import (
	"errors"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/gaukas/clienthellod"
	"go.uber.org/zap"
)

const (
	CaddyAppID = "clienthellod"

	DEFAULT_RESERVOIR_ENTRY_VALID_FOR   = 10 * time.Second
	DEFAULT_RESERVOIR_CLEANING_INTERVAL = 10 * time.Second
)

func init() {
	caddy.RegisterModule(Reservoir{})
}

// Reservoir implements caddy.App.
// It is used to store the ClientHello extracted from the incoming TLS
// by ListenerWrapper for later use by the Handler when ServeHTTP is called.
type Reservoir struct {
	ValidFor caddy.Duration `json:"valid_for,omitempty"`

	// CleanInterval is the interval at which the reservoir is cleaned
	// of expired entries.
	//
	// Deprecated: this field is no longer used. Each entry is cleaned on
	// its own schedule, based on its expiry time. Setting ValidFor is
	// sufficient.
	CleanInterval caddy.Duration `json:"clean_interval,omitempty"`

	tlsFingerprinter  *clienthellod.TLSFingerprinter
	quicFingerprinter *clienthellod.QUICFingerprinter

	logger *zap.Logger
}

// CaddyModule implements CaddyModule() of caddy.Module.
// It returns the Caddy module information.
func (Reservoir) CaddyModule() caddy.ModuleInfo { // skipcq: GO-W1029
	return caddy.ModuleInfo{
		ID: CaddyAppID,
		New: func() caddy.Module {
			reservoir := &Reservoir{
				ValidFor: caddy.Duration(DEFAULT_RESERVOIR_ENTRY_VALID_FOR),
				// CleanInterval: caddy.Duration(DEFAULT_RESERVOIR_CLEANING_INTERVAL),
			}

			return reservoir
		},
	}
}

// TLSFingerprinter returns the TLSFingerprinter instance.
func (r *Reservoir) TLSFingerprinter() *clienthellod.TLSFingerprinter { // skipcq: GO-W1029
	return r.tlsFingerprinter
}

// QUICFingerprinter returns the QUICFingerprinter instance.
func (r *Reservoir) QUICFingerprinter() *clienthellod.QUICFingerprinter { // skipcq: GO-W1029
	return r.quicFingerprinter
}

// Start implements Start() of caddy.App.
func (r *Reservoir) Start() error { // skipcq: GO-W1029
	if r.ValidFor <= 0 {
		return errors.New("validfor must be a positive duration")
	}

	// if r.CleanInterval <= 0 {
	// 	return errors.New("clean_interval must be a positive duration")
	// }

	r.logger.Info("clienthellod reservoir is started")

	return nil
}

// Stop implements Stop() of caddy.App.
func (r *Reservoir) Stop() error { // skipcq: GO-W1029
	r.quicFingerprinter.Close()
	r.tlsFingerprinter.Close()
	return nil
}

// Provision implements Provision() of caddy.Provisioner.
func (r *Reservoir) Provision(ctx caddy.Context) error { // skipcq: GO-W1029
	r.logger = ctx.Logger(r)
	r.tlsFingerprinter = clienthellod.NewTLSFingerprinterWithTimeout(time.Duration(r.ValidFor))
	r.quicFingerprinter = clienthellod.NewQUICFingerprinterWithTimeout(time.Duration(r.ValidFor))

	r.logger.Info("clienthellod reservoir is provisioned")
	return nil
}

var (
	_ caddy.App         = (*Reservoir)(nil)
	_ caddy.Provisioner = (*Reservoir)(nil)
)

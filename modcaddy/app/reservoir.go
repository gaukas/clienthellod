package app

import (
	"errors"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/gaukas/clienthellod"
	"go.uber.org/zap"
)

const (
	CaddyAppID = "clienthellod"

	DEFAULT_TLS_FP_TTL  = clienthellod.DEFAULT_TLSFINGERPRINT_EXPIRY  // TODO: select a reasonable value
	DEFAULT_QUIC_FP_TTL = clienthellod.DEFAULT_QUICFINGERPRINT_EXPIRY // TODO: select a reasonable value
)

func init() {
	caddy.RegisterModule(Reservoir{})
}

// Reservoir implements [caddy.App] and [caddy.Provisioner].
// It is used to store the ClientHello extracted from the incoming TLS
// by ListenerWrapper for later use by the Handler when ServeHTTP is called.
type Reservoir struct {
	// TlsTTL (Time-to-Live) is the duration for which each TLS fingerprint
	// is valid. The entry will remain in the reservoir for at most this
	// duration.
	//
	// There are scenarios an entry gets removed sooner than this duration, including
	// when a TLS ClientHello is successfully served by the handler.
	TlsTTL caddy.Duration `json:"tls_ttl,omitempty"`

	// QuicTTL (Time-to-Live) is the duration for which each QUIC fingerprint
	// is valid. The entry will remain in the reservoir for at most this
	// duration.
	//
	// Given the fact that some implementations would prefer reusing the previously established
	// QUIC connection instead of establishing a new one everytime, it is recommended to set
	// a longer TTL for QUIC.
	QuicTTL caddy.Duration `json:"quic_ttl,omitempty"`

	tlsFingerprinter        *clienthellod.TLSFingerprinter
	quicFingerprinter       *clienthellod.QUICFingerprinter
	mapLastQUICVisitorPerIP *sync.Map // sometimes even when a complete QUIC handshake is done, client decide to connect using HTTP/2

	logger *zap.Logger
}

// CaddyModule implements CaddyModule() of caddy.Module.
// It returns the Caddy module information.
func (Reservoir) CaddyModule() caddy.ModuleInfo { // skipcq: GO-W1029
	return caddy.ModuleInfo{
		ID: CaddyAppID,
		New: func() caddy.Module {
			reservoir := &Reservoir{
				TlsTTL:  caddy.Duration(DEFAULT_TLS_FP_TTL),
				QuicTTL: caddy.Duration(DEFAULT_QUIC_FP_TTL),
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

// NewQUICVisitor updates the map entry for the given IP address.
func (r *Reservoir) NewQUICVisitor(ip, fullKey string) { // skipcq: GO-W1029
	r.mapLastQUICVisitorPerIP.Store(ip, fullKey)

	// delete it after TTL if not updated
	go func() {
		<-time.After(time.Duration(r.QuicTTL))
		r.mapLastQUICVisitorPerIP.CompareAndDelete(ip, fullKey)
	}()
}

// GetLastQUICVisitor returns the last QUIC visitor for the given IP address.
func (r *Reservoir) GetLastQUICVisitor(ip string) (string, bool) { // skipcq: GO-W1029
	if v, ok := r.mapLastQUICVisitorPerIP.Load(ip); ok {
		if fullKey, ok := v.(string); ok {
			return fullKey, true
		}
	}
	return "", false
}

// Start implements Start() of caddy.App.
func (r *Reservoir) Start() error { // skipcq: GO-W1029
	if r.QuicTTL <= 0 || r.TlsTTL <= 0 {
		return errors.New("ttl must be a positive duration")
	}

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
	r.tlsFingerprinter = clienthellod.NewTLSFingerprinterWithTimeout(time.Duration(r.TlsTTL))
	r.quicFingerprinter = clienthellod.NewQUICFingerprinterWithTimeout(time.Duration(r.QuicTTL))
	r.mapLastQUICVisitorPerIP = new(sync.Map)

	r.logger = ctx.Logger(r)

	r.logger.Info("clienthellod reservoir is provisioned")
	return nil
}

var (
	_ caddy.App         = (*Reservoir)(nil)
	_ caddy.Provisioner = (*Reservoir)(nil)
)

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
	ValidFor      caddy.Duration `json:"valid_for,omitempty"`
	CleanInterval caddy.Duration `json:"clean_interval,omitempty"`

	chMap map[string]*struct {
		ch     *clienthellod.ClientHello
		expiry time.Time
	}
	mutex  *sync.Mutex
	ticker *time.Ticker
	logger *zap.Logger
}

// DepositClientHello stores the ClientHello extracted from the incoming TLS
// connection into the reservoir, with the client address as the key.
func (r *Reservoir) DepositClientHello(addr string, ch *clienthellod.ClientHello) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.chMap[addr] = &struct {
		ch     *clienthellod.ClientHello
		expiry time.Time
	}{ch, time.Now().Add(time.Duration(r.ValidFor))}
}

// WithdrawClientHello retrieves the ClientHello from the reservoir and
// deletes it from the reservoir, using the client address as the key.
func (r *Reservoir) WithdrawClientHello(addr string) (ch *clienthellod.ClientHello) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if v, ok := r.chMap[addr]; ok {
		if time.Now().Before(v.expiry) {
			ch = v.ch
		}
		delete(r.chMap, addr)
	}
	return
}

// CaddyModule implements CaddyModule() of caddy.Module.
// It returns the Caddy module information.
func (Reservoir) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: CaddyAppID,
		New: func() caddy.Module {
			return &Reservoir{
				ValidFor:      caddy.Duration(DEFAULT_RESERVOIR_ENTRY_VALID_FOR),
				CleanInterval: caddy.Duration(DEFAULT_RESERVOIR_CLEANING_INTERVAL),
				chMap: make(map[string]*struct {
					ch     *clienthellod.ClientHello
					expiry time.Time
				}),
				mutex: new(sync.Mutex),
			}
		},
	}
}

// Start implements Start() of caddy.App.
func (r *Reservoir) Start() error {
	if r.ValidFor <= 0 {
		r.ValidFor = caddy.Duration(DEFAULT_RESERVOIR_ENTRY_VALID_FOR)
	}

	if r.CleanInterval <= 0 {
		r.CleanInterval = caddy.Duration(DEFAULT_RESERVOIR_CLEANING_INTERVAL)
	}

	r.ticker = time.NewTicker(time.Duration(r.CleanInterval))
	go func() {
		for range r.ticker.C {
			r.mutex.Lock()
			for k, v := range r.chMap {
				if v.expiry.Before(time.Now()) {
					delete(r.chMap, k)
				}
			}
			r.mutex.Unlock()
		}
	}()
	return nil
}

// Stop implements Stop() of caddy.App.
func (r *Reservoir) Stop() error {
	if r.ticker == nil {
		return errors.New("reservoir is not started")
	}
	r.ticker.Stop()
	return nil
}

// Provision implements Provision() of caddy.Provisioner.
func (r *Reservoir) Provision(ctx caddy.Context) error {
	r.logger = ctx.Logger(r)
	r.logger.Info("reservoir is provisioned")
	return nil
}

var (
	_ caddy.App         = (*Reservoir)(nil)
	_ caddy.Provisioner = (*Reservoir)(nil)
)

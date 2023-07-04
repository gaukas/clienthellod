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
	mutex *sync.Mutex

	cipMap map[string]*struct {
		cip    *clienthellod.ClientInitialPacket
		expiry time.Time
	} // QUIC Client Initial Packet
	qmutex *sync.Mutex // QUIC mutex

	ticker *time.Ticker
	logger *zap.Logger
}

// CaddyModule implements CaddyModule() of caddy.Module.
// It returns the Caddy module information.
func (Reservoir) CaddyModule() caddy.ModuleInfo { // skipcq: GO-W1029
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
				cipMap: make(map[string]*struct {
					cip    *clienthellod.ClientInitialPacket
					expiry time.Time
				}),
				qmutex: new(sync.Mutex),
			}
		},
	}
}

// DepositClientHello stores the TLS ClientHello extracted from the incoming TLS
// connection into the reservoir, with the client address as the key.
func (r *Reservoir) DepositClientHello(addr string, ch *clienthellod.ClientHello) { // skipcq: GO-W1029
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.chMap[addr] = &struct {
		ch     *clienthellod.ClientHello
		expiry time.Time
	}{ch, time.Now().Add(time.Duration(r.ValidFor))}
}

// DepositQUICCIP stores the QUIC Client Initial Packet extracted from the incoming UDP datagram
// into the reservoir, with the client address as the key.
func (r *Reservoir) DepositQUICCIP(addr string, cip *clienthellod.ClientInitialPacket) { // skipcq: GO-W1029
	r.qmutex.Lock()
	defer r.qmutex.Unlock()
	r.lockedDepositQUICCIP(addr, cip)
}

// caller must hold the lock on r.qmutex
func (r *Reservoir) lockedDepositQUICCIP(addr string, cip *clienthellod.ClientInitialPacket) { // skipcq: GO-W1029
	r.cipMap[addr] = &struct {
		cip    *clienthellod.ClientInitialPacket
		expiry time.Time
	}{cip, time.Now().Add(time.Duration(r.ValidFor))}
}

// WithdrawClientHello retrieves the ClientHello from the reservoir and
// deletes it from the reservoir, using the client address as the key.
func (r *Reservoir) WithdrawClientHello(addr string) (ch *clienthellod.ClientHello) { // skipcq: GO-W1029
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

// WithdrawQUICCIP retrieves the QUIC Client Initial Packet from the reservoir and
// deletes it from the reservoir, using the client address as the key.
func (r *Reservoir) WithdrawQUICCIP(addr string) (cip *clienthellod.ClientInitialPacket) { // skipcq: GO-W1029
	r.qmutex.Lock()
	defer r.qmutex.Unlock()
	if v, ok := r.cipMap[addr]; ok {
		if time.Now().Before(v.expiry) {
			cip = v.cip
		}
		delete(r.cipMap, addr)
		// reinsert the QUIC Client Initial Packet into the reservoir
		// with a new expiry time
		r.lockedDepositQUICCIP(addr, cip)
	}
	return
}

// Start implements Start() of caddy.App.
func (r *Reservoir) Start() error { // skipcq: GO-W1029
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

			r.qmutex.Lock()
			for k, v := range r.cipMap {
				if v.expiry.Before(time.Now()) {
					delete(r.cipMap, k)
				}
			}
			r.qmutex.Unlock()
		}
	}()
	return nil
}

// Stop implements Stop() of caddy.App.
func (r *Reservoir) Stop() error { // skipcq: GO-W1029
	if r.ticker == nil {
		return errors.New("reservoir is not started")
	}
	r.ticker.Stop()
	return nil
}

// Provision implements Provision() of caddy.Provisioner.
func (r *Reservoir) Provision(ctx caddy.Context) error { // skipcq: GO-W1029
	r.logger = ctx.Logger(r)
	r.logger.Info("clienthellod reservoir is provisioned")
	return nil
}

var (
	_ caddy.App         = (*Reservoir)(nil)
	_ caddy.Provisioner = (*Reservoir)(nil)
)

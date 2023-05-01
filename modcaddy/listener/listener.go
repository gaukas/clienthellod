package listener

import (
	"errors"
	"net"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/gaukas/clienthellod"
	"github.com/gaukas/clienthellod/internal/utils"
	"github.com/gaukas/clienthellod/modcaddy/app"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
}

// ListenerWrapper implements caddy.ListenerWrapper.
// It is used to extract the ClientHello from the incoming TLS
// connection before it reaches the "tls" in caddy.listeners
//
// For clienthellod to work, it must be placed before the "tls" in
// the Caddyfile's listener_wrappers directive. For example:
//
//	listener_wrappers {
//		clienthellod
//		tls
//	}
type ListenerWrapper struct {
	TCP bool `json:"tcp,omitempty"`
	UDP bool `json:"udp,omitempty"`

	reservoir *app.Reservoir
	logger    *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.clienthellod",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

func (lw *ListenerWrapper) Provision(ctx caddy.Context) error {
	if !ctx.AppIsConfigured(app.CaddyAppID) {
		return errors.New("listener: clienthellod is not configured")
	}

	a, err := ctx.App(app.CaddyAppID)
	if err != nil {
		return err
	}
	lw.reservoir = a.(*app.Reservoir)
	lw.logger = ctx.Logger(lw)
	lw.logger.Info("clienthellod listener provisioned!")
	return nil
}

func (lw *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	lw.logger.Info("Wrapping listener " + l.Addr().String() + "on network " + l.Addr().Network() + "...")

	if l.Addr().Network() == "tcp" || l.Addr().Network() == "tcp4" || l.Addr().Network() == "tcp6" {
		if lw.TCP {
			return wrapTlsListener(l, lw.reservoir, lw.logger)
		} else {
			lw.logger.Debug("TCP not enabled. Skipping...")
		}
	} else {
		lw.logger.Debug("Not TCP. Skipping...")
	}

	return l
}

type tlsListener struct {
	net.Listener
	reservoir *app.Reservoir
	logger    *zap.Logger
}

func wrapTlsListener(in net.Listener, r *app.Reservoir, logger *zap.Logger) net.Listener {
	return &tlsListener{
		Listener:  in,
		reservoir: r,
		logger:    logger,
	}
}

func (l *tlsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return conn, err
	}

	ch, err := clienthellod.ReadClientHello(conn)
	if err == nil {
		l.logger.Debug("Depositing ClientHello from " + conn.RemoteAddr().String())
		l.reservoir.DepositClientHello(conn.RemoteAddr().String(), ch)
	} else {
		l.logger.Error("Failed to read ClientHello from "+conn.RemoteAddr().String(), zap.Error(err))
	}

	// No matter what happens, rewind the connection
	return utils.RewindConn(conn, ch.Raw())
}

func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "tcp":
				if lw.TCP {
					return d.Err("clienthellod: tcp already specified")
				}
				lw.TCP = true
			case "udp":
				if lw.UDP {
					return d.Err("clienthellod: udp already specified")
				}
				lw.UDP = true
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)

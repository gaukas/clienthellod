package listener

import (
	"errors"
	"io"
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

	logger       *zap.Logger
	reservoir    *app.Reservoir
	udpListener  *net.IPConn
	udp6Listener *net.IPConn
}

// CaddyModule returns the Caddy module information.
func (ListenerWrapper) CaddyModule() caddy.ModuleInfo { // skipcq: GO-W1029
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.clienthellod",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

func (lw *ListenerWrapper) Cleanup() error { // skipcq: GO-W1029
	if lw.UDP && lw.udpListener != nil {
		return lw.udpListener.Close()
	}
	if lw.UDP && lw.udp6Listener != nil {
		return lw.udp6Listener.Close()
	}
	return nil
}

func (lw *ListenerWrapper) Provision(ctx caddy.Context) error { // skipcq: GO-W1029
	// logger
	lw.logger = ctx.Logger(lw)
	lw.logger.Info("clienthellod listener logger loaded.")

	// reservoir
	if !ctx.AppIsConfigured(app.CaddyAppID) {
		return errors.New("clienthellod listener: global reservoir is not configured")
	}
	a, err := ctx.App(app.CaddyAppID)
	if err != nil {
		return err
	}
	lw.reservoir = a.(*app.Reservoir)
	lw.logger.Info("clienthellod listener reservoir loaded.")

	// UDP listener if enabled and not already provisioned
	if lw.UDP && lw.udpListener == nil {
		lw.udpListener, err = net.ListenIP("ip4:udp", &net.IPAddr{})
		if err != nil {
			return err
		}
		go lw.udpLoop()

		lw.udp6Listener, err = net.ListenIP("ip6:udp", &net.IPAddr{})
		if err != nil {
			return err
		}
		go lw.udp6Loop()

		go lw.logger.Info("clienthellod listener UDP listener loaded.")
	}

	lw.logger.Info("clienthellod listener provisioned.")
	return nil
}

func (lw *ListenerWrapper) udpLoop() { // skipcq: GO-W1029
	for {
		var buf [2048]byte
		n, ipAddr, err := lw.udpListener.ReadFromIP(buf[:])
		if err != nil {
			lw.logger.Error("UDP read error", zap.Error(err))
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return // return when listener is closed
			}
			continue
		}
		// lw.logger.Debug("Received UDP packet from " + ipAddr.String())

		// Parse UDP Packet
		udpPkt, err := utils.ParseUDPPacket(buf[:n])
		if err != nil {
			lw.logger.Error("Failed to parse UDP packet", zap.Error(err))
			continue
		}
		if udpPkt.DstPort != 443 {
			continue
		}
		udpAddr := &net.UDPAddr{IP: ipAddr.IP, Port: int(udpPkt.SrcPort)}
		// lw.logger.Debug("Parsed UDP packet from " + udpAddr.String())

		cip, err := clienthellod.ParseQUICCIP(udpPkt.Payload)
		if err != nil {
			lw.logger.Debug("Failed to parse QUIC CIP: ", zap.Error(err))
			continue
		}
		// lw.logger.Debug("Depositing QClientHello from " + ipAddr.String())
		lw.reservoir.DepositQUICCIP(udpAddr.String(), cip)
	}
}

func (lw *ListenerWrapper) udp6Loop() { // skipcq: GO-W1029
	for {
		var buf [2048]byte
		n, ipAddr, err := lw.udp6Listener.ReadFromIP(buf[:])
		if err != nil {
			lw.logger.Error("UDP read error", zap.Error(err))
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) {
				return // return when listener is closed
			}
			continue
		}
		// lw.logger.Debug("Received UDP packet from " + ipAddr.String())

		// Parse UDP Packet
		udpPkt, err := utils.ParseUDPPacket(buf[:n])
		if err != nil {
			lw.logger.Error("Failed to parse UDP packet", zap.Error(err))
			continue
		}
		if udpPkt.DstPort != 443 {
			continue
		}
		udpAddr := &net.UDPAddr{IP: ipAddr.IP, Port: int(udpPkt.SrcPort)}
		// lw.logger.Debug("Parsed UDP packet from " + udpAddr.String())

		cip, err := clienthellod.ParseQUICCIP(udpPkt.Payload)
		if err != nil {
			continue
		}
		// lw.logger.Debug("Depositing QClientHello from " + ipAddr.String())
		lw.reservoir.DepositQUICCIP(udpAddr.String(), cip)
	}
}

func (lw *ListenerWrapper) WrapListener(l net.Listener) net.Listener { // skipcq: GO-W1029
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
		l.reservoir.DepositClientHello(conn.RemoteAddr().String(), ch)
		l.logger.Debug("Deposited ClientHello from " + conn.RemoteAddr().String())
	} else {
		l.logger.Error("Failed to read ClientHello from "+conn.RemoteAddr().String(), zap.Error(err))
	}

	// No matter what happens, rewind the connection
	return utils.RewindConn(conn, ch.Raw())
}

func (lw *ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { // skipcq: GO-W1029
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
	_ caddy.CleanerUpper    = (*ListenerWrapper)(nil)
	_ caddy.Provisioner     = (*ListenerWrapper)(nil)
	_ caddy.ListenerWrapper = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler = (*ListenerWrapper)(nil)
)

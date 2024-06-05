package clienthellod

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaukas/clienthellod/internal/utils"
)

const DEFAULT_TLSFINGERPRINT_EXPIRY = 5 * time.Second

// TLSFingerprinter can be used to fingerprint TLS connections.
type TLSFingerprinter struct {
	mapClientHellos *sync.Map

	timeout time.Duration
	closed  atomic.Bool
}

// NewTLSFingerprinter creates a new TLSFingerprinter.
func NewTLSFingerprinter() *TLSFingerprinter {
	return &TLSFingerprinter{
		mapClientHellos: new(sync.Map),
		closed:          atomic.Bool{},
	}
}

// NewTLSFingerprinterWithTimeout creates a new TLSFingerprinter with a timeout.
func NewTLSFingerprinterWithTimeout(timeout time.Duration) *TLSFingerprinter {
	return &TLSFingerprinter{
		mapClientHellos: new(sync.Map),
		timeout:         timeout,
		closed:          atomic.Bool{},
	}
}

// SetTimeout sets the timeout for the TLSFingerprinter.
func (tfp *TLSFingerprinter) SetTimeout(timeout time.Duration) {
	tfp.timeout = timeout
}

// HandleMessage handles a message.
func (tfp *TLSFingerprinter) HandleMessage(from string, p []byte) error {
	if tfp.closed.Load() {
		return errors.New("TLSFingerprinter closed")
	}

	ch, err := UnmarshalClientHello(p)
	if err != nil {
		return err
	}

	tfp.mapClientHellos.Store(from, ch)
	go func(timeoutOverride time.Duration, key string, oldCh *ClientHello) {
		if timeoutOverride == time.Duration(0) {
			<-time.After(DEFAULT_TLSFINGERPRINT_EXPIRY)
		} else {
			<-time.After(timeoutOverride)
		}
		// tfp.mapClientHellos.Delete(key)
		tfp.mapClientHellos.CompareAndDelete(key, oldCh)
	}(tfp.timeout, from, ch)

	return nil
}

// HandleTCPConn handles a TCP connection.
func (tfp *TLSFingerprinter) HandleTCPConn(conn net.Conn) (rewindConn net.Conn, err error) {
	if tfp.closed.Load() {
		return nil, errors.New("TLSFingerprinter closed")
	}

	ch, err := ReadClientHello(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read ClientHello from connection: %w", err)
	}

	if err = ch.ParseClientHello(); err != nil {
		return nil, fmt.Errorf("failed to parse ClientHello: %w", err)
	}

	tfp.mapClientHellos.Store(conn.RemoteAddr().String(), ch)
	go func(timeoutOverride time.Duration, key string, oldCh *ClientHello) {
		if timeoutOverride == time.Duration(0) {
			<-time.After(DEFAULT_TLSFINGERPRINT_EXPIRY)
		} else {
			<-time.After(timeoutOverride)
		}
		// tfp.mapClientHellos.Delete(key)
		tfp.mapClientHellos.CompareAndDelete(key, oldCh)
	}(tfp.timeout, conn.RemoteAddr().String(), ch)

	return utils.RewindConn(conn, ch.Raw())
}

// Peek looks up a ClientHello for a given key.
func (tfp *TLSFingerprinter) Peek(from string) *ClientHello {
	ch, ok := tfp.mapClientHellos.Load(from)
	if !ok {
		return nil
	}

	clientHello, ok := ch.(*ClientHello)
	if !ok {
		return nil
	}

	return clientHello
}

// Pop looks up a ClientHello for a given key and deletes it from the
// fingerprinter if found.
func (tfp *TLSFingerprinter) Pop(from string) *ClientHello {
	ch, ok := tfp.mapClientHellos.LoadAndDelete(from)
	if !ok {
		return nil
	}

	clientHello, ok := ch.(*ClientHello)
	if !ok {
		return nil
	}

	return clientHello
}

// Close closes the TLSFingerprinter.
func (tfp *TLSFingerprinter) Close() {
	tfp.closed.Store(true)
}

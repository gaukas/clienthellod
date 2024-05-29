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

const DEFAULT_TLSFINGERPRINT_EXPIRY = 10 * time.Second

type TLSFingerprinter struct {
	mapClientHellos *sync.Map

	timeout time.Duration
	closed  atomic.Bool
}

func NewTLSFingerprinter() *TLSFingerprinter {
	return &TLSFingerprinter{
		mapClientHellos: new(sync.Map),
		closed:          atomic.Bool{},
	}
}

func NewTLSFingerprinterWithTimeout(timeout time.Duration) *TLSFingerprinter {
	return &TLSFingerprinter{
		mapClientHellos: new(sync.Map),
		timeout:         timeout,
		closed:          atomic.Bool{},
	}
}

func (tfp *TLSFingerprinter) SetTimeout(timeout time.Duration) {
	tfp.timeout = timeout
}

func (tfp *TLSFingerprinter) HandleMessage(from string, p []byte) error {
	if tfp.closed.Load() {
		return errors.New("TLSFingerprinter closed")
	}

	ch, err := UnmarshalClientHello(p)
	if err != nil {
		return err
	}

	tfp.mapClientHellos.Store(from, ch)
	go func() {
		if tfp.timeout == time.Duration(0) {
			<-time.After(DEFAULT_TLSFINGERPRINT_EXPIRY)
		} else {
			<-time.After(tfp.timeout)
		}
		tfp.mapClientHellos.Delete(from)
	}()

	return nil
}

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
	go func() {
		if tfp.timeout == time.Duration(0) {
			<-time.After(DEFAULT_TLSFINGERPRINT_EXPIRY)
		} else {
			<-time.After(tfp.timeout)
		}
		tfp.mapClientHellos.Delete(conn.RemoteAddr().String())
	}()

	return utils.RewindConn(conn, ch.Raw())
}

func (tfp *TLSFingerprinter) Lookup(from string) *ClientHello {
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

func (tfp *TLSFingerprinter) Close() {
	tfp.closed.Store(true)
}
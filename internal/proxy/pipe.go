package proxy

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
)

func pipeBidirectional(log *logrus.Entry, client, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(upstream, client); err != nil && !isClosedNetworkError(err) {
			log.WithError(err).Debug("client -> upstream copy error")
		}
		closeWrite(upstream)
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(client, upstream); err != nil && !isClosedNetworkError(err) {
			log.WithError(err).Debug("upstream -> client copy error")
		}
		closeWrite(client)
	}()

	wg.Wait()
}

func closeWrite(conn net.Conn) {
	type closeWriter interface {
		CloseWrite() error
	}
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

func isClosedNetworkError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	return false
}

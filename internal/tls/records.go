package tls

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"
)

const (
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
)

var (
	// ErrNotHandshake indicates the record content type is not Handshake.
	ErrNotHandshake = errors.New("record is not a handshake")
	// ErrNotClientHello indicates the handshake message type is not ClientHello.
	ErrNotClientHello = errors.New("handshake is not a ClientHello")
	// ErrRecordTooLarge is returned when the TLS record exceeds the configured cap.
	ErrRecordTooLarge = errors.New("record exceeds configured limit")
	// ErrHandshakeTooShort signals the handshake payload is smaller than the minimum header.
	ErrHandshakeTooShort = errors.New("handshake record too short")
)

// Record represents a single TLS record payload.
type Record struct {
	ContentType uint8
	Version     uint16
	Payload     []byte
}

// ReadResult bundles the parsed record with the raw bytes consumed from the client.
type ReadResult struct {
	Record *Record
	Raw    []byte
}

// ReadInitialRecord reads the first TLS record from conn with an optional timeout and size cap.
func ReadInitialRecord(conn net.Conn, timeout time.Duration, maxSize int) (*ReadResult, error) {
	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer conn.SetReadDeadline(time.Time{})
	}

	header := make([]byte, 5)
	total := make([]byte, 0, 5+maxSize)

	n, err := io.ReadFull(conn, header)
	total = append(total, header[:n]...)
	if err != nil {
		if len(total) == 0 {
			return nil, err
		}
		return &ReadResult{Raw: total}, err
	}

	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length > maxSize {
		return &ReadResult{Raw: total}, ErrRecordTooLarge
	}

	payload := make([]byte, length)
	m, err := io.ReadFull(conn, payload)
	total = append(total, payload[:m]...)
	if err != nil {
		return &ReadResult{Raw: total}, err
	}

	return &ReadResult{
		Record: &Record{
			ContentType: header[0],
			Version:     binary.BigEndian.Uint16(header[1:3]),
			Payload:     payload,
		},
		Raw: append([]byte(nil), total...),
	}, nil
}

// SplitClientHello divides a ClientHello handshake across one or two new TLS records.
func SplitClientHello(rec *Record, first int) ([]Record, error) {
	if rec.ContentType != recordTypeHandshake {
		return nil, ErrNotHandshake
	}
	if len(rec.Payload) < 4 {
		return nil, ErrHandshakeTooShort
	}
	if rec.Payload[0] != handshakeTypeClientHello {
		return nil, ErrNotClientHello
	}

	bodyLength := int(rec.Payload[1])<<16 | int(rec.Payload[2])<<8 | int(rec.Payload[3])
	if bodyLength+4 != len(rec.Payload) {
		return nil, fmt.Errorf("handshake length mismatch: header=%d payload=%d", bodyLength, len(rec.Payload)-4)
	}

	if first <= 0 || first >= len(rec.Payload) {
		return []Record{{
			ContentType: rec.ContentType,
			Version:     rec.Version,
			Payload:     append([]byte(nil), rec.Payload...),
		}}, nil
	}

	firstPayload := append([]byte(nil), rec.Payload[:first]...)
	secondPayload := append([]byte(nil), rec.Payload[first:]...)

	return []Record{
		{ContentType: rec.ContentType, Version: rec.Version, Payload: firstPayload},
		{ContentType: rec.ContentType, Version: rec.Version, Payload: secondPayload},
	}, nil
}

// WriteRecords emits one or more TLS records to conn with an optional random gap between the first two.
func WriteRecords(conn net.Conn, records []Record, gapMin, gapMax time.Duration) error {
	for idx, rec := range records {
		length := len(rec.Payload)
		if length > 0xFFFF {
			return fmt.Errorf("record payload too large: %d", length)
		}
		header := []byte{
			rec.ContentType,
			byte(rec.Version >> 8),
			byte(rec.Version),
			byte(length >> 8),
			byte(length),
		}

		if _, err := conn.Write(header); err != nil {
			return fmt.Errorf("write record header: %w", err)
		}
		if length > 0 {
			if _, err := conn.Write(rec.Payload); err != nil {
				return fmt.Errorf("write record payload: %w", err)
			}
		}

		if idx == 0 && len(records) > 1 {
			gap := selectGapDuration(gapMin, gapMax)
			if gap > 0 {
				time.Sleep(gap)
			}
		}
	}
	return nil
}

func selectGapDuration(min, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	if min < 0 {
		min = 0
	}
	if max < min {
		max = min
	}
	span := max - min
	if span <= 0 {
		return max
	}
	n := rand.Int63n(int64(span) + 1)
	return min + time.Duration(n)
}

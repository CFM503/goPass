package engine

import (
	"encoding/binary"
	"errors"
)

// Sentinel errors - pre-allocated to avoid fmt.Errorf allocations in hot path
var (
	ErrNotTLSHandshake    = errors.New("not a tls handshake")
	ErrIncompleteRecord   = errors.New("incomplete tls record")
	ErrNotClientHello     = errors.New("not a client hello")
	ErrIncompleteClient   = errors.New("incomplete client hello")
	ErrNoExtensions       = errors.New("no extensions")
	ErrSNINotFound        = errors.New("sni not found")
)

// ExtractSNI 解析 TLS ClientHello 包并提取 Server Name Indication (SNI)
func ExtractSNI(data []byte) (string, error) {
	if len(data) < 5 {
		return "", ErrNotTLSHandshake
	}
	if data[0] != 22 {
		return "", ErrNotTLSHandshake
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return "", ErrIncompleteRecord
	}

	rest := data[5 : 5+recordLen]
	if len(rest) < 4 {
		return "", ErrNotClientHello
	}
	if rest[0] != 1 {
		return "", ErrNotClientHello
	}
	msgLen := int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
	if len(rest) < 4+msgLen {
		return "", ErrIncompleteClient
	}

	offset := 4 + 2 + 32
	if offset >= len(rest) {
		return "", ErrIncompleteClient
	}
	sessionIDLen := int(rest[offset])
	offset += 1 + sessionIDLen
	if offset+2 >= len(rest) {
		return "", ErrIncompleteClient
	}

	cipherSuitesLen := int(binary.BigEndian.Uint16(rest[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	if offset >= len(rest) {
		return "", ErrIncompleteClient
	}

	compMethodsLen := int(rest[offset])
	offset += 1 + compMethodsLen

	if offset+2 > len(rest) {
		return "", ErrNoExtensions
	}

	extsLen := int(binary.BigEndian.Uint16(rest[offset : offset+2]))
	offset += 2
	if offset+extsLen > len(rest) {
		return "", ErrSNINotFound
	}

	exts := rest[offset : offset+extsLen]
	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[0:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+extLen > len(exts) {
			break
		}
		if extType == 0 {
			snData := exts[4 : 4+extLen]
			if len(snData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(snData[0:2]))
				if listLen+2 <= len(snData) {
					snList := snData[2 : listLen+2]
					if len(snList) >= 3 && snList[0] == 0 {
						nameLen := int(binary.BigEndian.Uint16(snList[1:3]))
						if 3+nameLen <= len(snList) {
							return string(snList[3 : 3+nameLen]), nil
						}
					}
				}
			}
		}
		exts = exts[4+extLen:]
	}

	return "", ErrSNINotFound
}

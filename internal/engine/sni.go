package engine

import (
	"encoding/binary"
	"fmt"
)

// ExtractSNI parses a TLS ClientHello and returns the hostname from the SNI extension.
// This parser intentionally has no allocations proportional to the hostname payload.
func ExtractSNI(data []byte) (string, error) {
	if len(data) < 5 || data[0] != 22 {
		return "", fmt.Errorf("not a TLS handshake record")
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if recordLen <= 0 || len(data) < 5+recordLen {
		return "", fmt.Errorf("incomplete TLS record")
	}

	rest := data[5 : 5+recordLen]
	if len(rest) < 4 || rest[0] != 1 {
		return "", fmt.Errorf("not a ClientHello")
	}
	msgLen := int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
	if msgLen < 34 || 4+msgLen > len(rest) {
		return "", fmt.Errorf("incomplete ClientHello")
	}

	// Handshake header + legacy_version + random.
	offset := 4 + 2 + 32
	if offset >= len(rest) {
		return "", fmt.Errorf("ClientHello too short")
	}

	sessionIDLen := int(rest[offset])
	offset++
	if offset+sessionIDLen > len(rest) {
		return "", fmt.Errorf("invalid session ID length")
	}
	offset += sessionIDLen

	if offset+2 > len(rest) {
		return "", fmt.Errorf("missing cipher suites")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(rest[offset : offset+2]))
	offset += 2
	if offset+cipherSuitesLen > len(rest) {
		return "", fmt.Errorf("invalid cipher suites length")
	}
	offset += cipherSuitesLen

	if offset >= len(rest) {
		return "", fmt.Errorf("missing compression methods")
	}
	compMethodsLen := int(rest[offset])
	offset++
	if offset+compMethodsLen > len(rest) {
		return "", fmt.Errorf("invalid compression methods length")
	}
	offset += compMethodsLen

	if offset+2 > len(rest) {
		return "", fmt.Errorf("missing extensions")
	}
	extsLen := int(binary.BigEndian.Uint16(rest[offset : offset+2]))
	offset += 2
	if offset+extsLen > len(rest) {
		return "", fmt.Errorf("invalid extensions length")
	}

	exts := rest[offset : offset+extsLen]
	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		if extLen > len(exts)-4 {
			return "", fmt.Errorf("invalid extension length")
		}
		if extType == 0 {
			snData := exts[4 : 4+extLen]
			if len(snData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(snData[:2]))
				if listLen <= len(snData)-2 {
					snList := snData[2 : 2+listLen]
					for len(snList) >= 3 {
						nameType := snList[0]
						nameLen := int(binary.BigEndian.Uint16(snList[1:3]))
						if nameLen > len(snList)-3 {
							return "", fmt.Errorf("invalid server name length")
						}
						if nameType == 0 && nameLen > 0 {
							return string(snList[3 : 3+nameLen]), nil
						}
						snList = snList[3+nameLen:]
					}
				}
			}
		}
		exts = exts[4+extLen:]
	}

	return "", fmt.Errorf("SNI not found")
}

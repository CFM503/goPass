package engine

import (
	"encoding/binary"
	"fmt"
)

// ExtractSNI 解析 TLS ClientHello 包并提取 Server Name Indication (SNI)
func ExtractSNI(data []byte) (string, error) {
	if len(data) < 5 {
		return "", fmt.Errorf("tls record too short")
	}
	// TLS Handshake (Content Type 22)
	if data[0] != 22 {
		return "", fmt.Errorf("not a tls handshake")
	}
	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return "", fmt.Errorf("incomplete tls record")
	}

	rest := data[5 : 5+recordLen]
	if len(rest) < 4 {
		return "", fmt.Errorf("handshake message too short")
	}
	// Client Hello (Handshake Type 1)
	if rest[0] != 1 {
		return "", fmt.Errorf("not a client hello")
	}
	msgLen := int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
	if len(rest) < 4+msgLen {
		return "", fmt.Errorf("incomplete client hello")
	}

	// Skip 4 bytes header + 2 bytes version (3, 3) + 32 bytes random
	offset := 4 + 2 + 32
	if offset >= len(rest) {
		return "", fmt.Errorf("too short for session id")
	}
	sessionIDLen := int(rest[offset])
	offset += 1 + sessionIDLen
	if offset+2 >= len(rest) {
		return "", fmt.Errorf("too short for cipher suites")
	}

	cipherSuitesLen := int(binary.BigEndian.Uint16(rest[offset : offset+2]))
	offset += 2 + cipherSuitesLen
	if offset >= len(rest) {
		return "", fmt.Errorf("too short for compression methods")
	}

	compMethodsLen := int(rest[offset])
	offset += 1 + compMethodsLen

	// Extensions
	if offset+2 > len(rest) {
		return "", fmt.Errorf("no extensions")
	}

	extsLen := int(binary.BigEndian.Uint16(rest[offset : offset+2]))
	offset += 2
	if offset+extsLen > len(rest) {
		return "", fmt.Errorf("extensions run out of bounds")
	}

	exts := rest[offset : offset+extsLen]
	for len(exts) >= 4 {
		extType := binary.BigEndian.Uint16(exts[0:2])
		extLen := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+extLen > len(exts) {
			break
		}
		if extType == 0 { // Server Name Indication
			snData := exts[4 : 4+extLen]
			if len(snData) >= 2 {
				listLen := int(binary.BigEndian.Uint16(snData[0:2]))
				if listLen+2 <= len(snData) {
					snList := snData[2 : listLen+2]
					if len(snList) >= 3 && snList[0] == 0 { // host_name type
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

	return "", fmt.Errorf("sni not found")
}

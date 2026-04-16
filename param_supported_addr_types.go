// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrInvalidAddrType is returned if an unknown address type is specified.
var ErrInvalidAddrType = errors.New("invalid address type")

type paramSupportedAddrTypes struct {
	paramHeader
	addrTypes []paramType
}

func (r *paramSupportedAddrTypes) marshal() ([]byte, error) {
	r.typ = supportedAddrTypes
	r.raw = make([]byte, len(r.addrTypes)*2)
	i := 0
	for _, a := range r.addrTypes {
		binary.BigEndian.PutUint16(r.raw[i:], uint16(a))
		i += 2
	}

	return r.paramHeader.marshal()
}

func (r *paramSupportedAddrTypes) unmarshal(raw []byte) (param, error) {
	err := r.paramHeader.unmarshal(raw)
	if err != nil {
		return nil, err
	}
	if len(r.raw)%2 == 1 {
		return nil, ErrInvalidChunkLength
	}

	i := 0
	for i < len(r.raw) {
		a := paramType(binary.BigEndian.Uint16(r.raw[i:]))
		switch a {
		case ipV4Addr, ipV6Addr, hostNameAddr:
			r.addrTypes = append(r.addrTypes, a)
		default:
			return nil, fmt.Errorf("%w: %v", ErrInvalidAddrType, a)
		}

		i += 2
	}

	return r, nil
}

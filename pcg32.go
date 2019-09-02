package fastrand

import (
	"crypto/rand"
	"encoding/binary"
)

const inc = uint64(0xda3e39cb94b95bdb)

var randomBytes, _ = GenerateRandomBytes(8)
var state = binary.BigEndian.Uint64(randomBytes)

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// PCG32 returns a random unsigned 32 bit integer using PCG.
func PCG32() uint32 {
	xorshifted := uint32((((state >> 18) ^ state) >> 27) & 0xffffffff)
	rot := uint32(state >> 59)
	state = (state*uint64(0x5851f42d4c957f2d) + inc) & uint64(0xffffffffffffffff)

	return (xorshifted >> rot) | ((xorshifted << (-rot & 31)) & 0xffffffff)
}

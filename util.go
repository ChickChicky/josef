package josef

import (
	"crypto/aes"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
)

// TODO: Make errors better

const KeySize = 64
const BlockSize = 16

type JosefError struct { m string }

func (e JosefError) Error() string {
	return e.m
}

type anyInt interface {~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr}

func ceildiv[T anyInt](x T, y T) T {
	return (x + y - 1) / y
}

func roundup[T anyInt](x T, y T) T {
	m := x%y
	if m == 0 {
		return x
	} else {
		return x + (y - m)
	}
}

var pathSalt = [BlockSize]byte{
	0x74, 0x89, 0x9f, 0x46, 0x48, 0xbb, 0x16, 0x97, 0x62, 0xc6, 0x2a, 0xad, 0x40, 0x97, 0xa5, 0x9a,
}

func debug(l *slog.Logger, f string, a ...any) {
	if l == nil {
		return
	}
	if len(a) == 0 {
		l.Debug(f)
	} else {
		l.Debug(fmt.Sprintf(f, a...))
	}
}

func cipherPath(key [KeySize]byte, path string) string {
	c, err := aes.NewCipher(key[:32])
	if err != nil {
		panic(err)
	}
	
	var bin [BlockSize]byte
	var bout [BlockSize]byte
	
	copy(bin[:], pathSalt[:])
	c.Encrypt(bout[:], bin[:])
	
	parts := []string{}
	{
		hash := sha512.Sum512(bout[:])
		parts = append(parts, hex.EncodeToString(hash[:]))
	}

	for seg := range strings.SplitSeq(filepath.Clean("/"+path), "/") {
		if len(seg) <= 0 { continue }
		
		bytes := append([]byte{byte(len(seg))}, []byte(seg)...)
		n := ceildiv(len(bytes), BlockSize)
		out := make([]byte, n*BlockSize)
		
		for i := range n {
			copy(bin[:], bytes[i*BlockSize:])
			for j := range BlockSize {
				bin[j] ^= bout[j] ^ key[32+j]
			}
			c.Encrypt(bout[:], bin[:])
			copy(out[i*BlockSize:], bout[:])
		}
		
		parts = append(parts, hex.EncodeToString(out))
	}

	return filepath.Clean("/"+strings.Join(parts, "/"))
}

func decipherPath(key [KeySize]byte, path string) (string, error) {
	c, err := aes.NewCipher(key[:32])
	if err != nil {
		panic(err)
	}
	
	var bout [BlockSize]byte
	var block [BlockSize]byte
	
	c.Encrypt(bout[:], pathSalt[:])
	
	parts := []string{}
	
	first := true
	for seg := range strings.SplitSeq(filepath.Clean("/"+path), "/") {
		if len(seg) <= 0 { continue }
		if first {
			hash := sha512.Sum512(bout[:])
			if hex.EncodeToString(hash[:]) != seg {
				return "", JosefError{m: "Bad root"}
			}
			first = false
			continue
		}
		ciphered, err := hex.DecodeString(seg)
		if err != nil {
			return "", err
		}
		if len(ciphered)%BlockSize != 0 {
			return "", JosefError{m: "Bad segment length"}
		}
		n := len(ciphered)/BlockSize
		for i := range n {
			off := i*BlockSize
			c.Decrypt(block[off:], ciphered[off:])
			for j := range BlockSize {
				block[off+j] ^= bout[j] ^ key[32+j]
			}
			copy(bout[:], ciphered[off:])
		}
		parts = append(parts, string(block[1:block[0]+1]))
	}
	return filepath.Clean("/"+strings.Join(parts, "/")), nil
}

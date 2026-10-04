package josef

import (
	"crypto/aes"
	"crypto/sha512"
	"encoding/hex"
	"path/filepath"
	"strings"
)

const keySize = 64
const blockSize = 16

type JosefError struct { m string }

func (e JosefError) Error() string {
	return e.m
}

type anyInt interface {~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr}

func ceildiv[T anyInt](x T, y T) T {
	return (x + y - 1) / y
}

func roundup[T anyInt](x T, y T) T {
	if x%y == 0 {
		return x
	} else {
		return x + (y - x%y)
	}
}

var pathSalt = [blockSize]byte{
	0x74, 0x89, 0x9f, 0x46, 0x48, 0xbb, 0x16, 0x97, 0x62, 0xc6, 0x2a, 0xad, 0x40, 0x97, 0xa5, 0x9a,
}

func cipherPath(key [keySize]byte, path string) string {
	c, err := aes.NewCipher(key[:32])
	if err != nil {
		panic(err)
	}
	
	var bin [blockSize]byte
	var bout [blockSize]byte
	
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
		n := ceildiv(len(bytes), blockSize)
		out := make([]byte, n*blockSize)
		
		for i := range n {
			copy(bin[:], bytes[i*blockSize:])
			for j := range blockSize {
				bin[j] ^= bout[j] ^ key[32+j]
			}
			c.Encrypt(bout[:], bin[:])
			copy(out[i*blockSize:], bout[:])
		}
		
		parts = append(parts, hex.EncodeToString(out))
	}

	return filepath.Clean("/"+strings.Join(parts, "/"))
}

func decipherPath(key [keySize]byte, path string) (string, error) {
	c, err := aes.NewCipher(key[:32])
	if err != nil {
		panic(err)
	}
	
	var bout [blockSize]byte
	var block [blockSize]byte
	
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
		if len(ciphered)%blockSize != 0 {
			return "", JosefError{m: "Bad segment length"}
		}
		n := len(ciphered)/blockSize
		for i := range n {
			off := i*blockSize
			c.Decrypt(block[off:], ciphered[off:])
			for j := range blockSize {
				block[off+j] ^= bout[j] ^ key[32+j]
			}
			copy(bout[:], ciphered[off:])
		}
		parts = append(parts, string(block[1:block[0]+1]))
	}
	return filepath.Clean("/"+strings.Join(parts, "/")), nil
}

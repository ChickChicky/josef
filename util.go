package josef

import (
	"crypto/aes"
	"crypto/sha512"
	"encoding/hex"
	"path/filepath"
	"strings"
)

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

var pathSalt = [32]byte{
	0x74, 0x89, 0x9f, 0x46, 0x48, 0xbb, 0x16, 0x97, 0x62, 0xc6, 0x2a, 0xad, 0x40, 0x97, 0xa5, 0x9a,
	0x83, 0x0b, 0x3b, 0x7e, 0xc8, 0xbf, 0xfb, 0x97, 0xda, 0x15, 0xd1, 0x12, 0x3b, 0x0b, 0x10, 0x89,
}

func cipherPath(key [64]byte, path string) string {
	// h := sha512.New()
	// s := make([]byte, 64)
	// parts := []string{}
	// var err error
	// for it := range strings.SplitSeq(filepath.Clean("/"+path), "/") {
	// 	h.Reset()
	// 	if _, err = h.Write(d.key); err != nil {
	// 		panic(err)
	// 	}
	// 	if _, err = h.Write(s); err != nil {
	// 		panic(err)
	// 	}
	// 	if _, err = h.Write([]byte(it)); err != nil {
	// 		panic(err)
	// 	}
	// 	s = h.Sum(nil)
	// 	parts = append(parts, hex.EncodeToString(s))
	// }
	// return filepath.Clean("/"+strings.Join(parts, "/"))
	c, err := aes.NewCipher(key[:32])
	if err != nil {
		panic(err)
	}
	bs := c.BlockSize()
	bin := make([]byte, bs)
	bout := make([]byte, bs)
	copy(bin, pathSalt[:])
	c.Encrypt(bout, bin)
	hash := sha512.Sum512(bout)
	parts := []string{hex.EncodeToString(hash[:])}
	for seg := range strings.SplitSeq(filepath.Clean("/"+path), "/") {
		if len(seg) <= 0 { continue }
		bytes := append([]byte{byte(len(seg))}, []byte(seg)...)
		n := ceildiv(len(bytes), bs)
		out := make([]byte, n*bs)
		for i := range n {
			copy(bin, bytes[i*bs:])
			for j := range bs {
				bin[j] ^= bout[j] ^ key[32+j%(len(key)-32)]
			}
			c.Encrypt(bout, bin)
			copy(out[i*bs:], bout)
		}
		parts = append(parts, hex.EncodeToString(out))
	}
	return filepath.Clean("/"+strings.Join(parts, "/"))
}

func decipherPath(key [64]byte, path string) (string, error) {
	c, err := aes.NewCipher(key[:32])
	if err != nil {
		panic(err)
	}
	bs := c.BlockSize()
	bout := make([]byte, bs)
	c.Encrypt(bout, pathSalt[:])
	first := true
	block := make([]byte, bs)
	parts := []string{}
	for seg := range strings.SplitSeq(filepath.Clean("/"+path), "/") {
		if len(seg) <= 0 { continue }
		if first {
			hash := sha512.Sum512(bout)
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
		if len(ciphered)%bs != 0 {
			return "", JosefError{m: "Bad segment length"}
		}
		n := len(ciphered)/bs
		if len(block) < len(ciphered) {
			block = make([]byte, len(ciphered))
		}
		for i := range n {
			off := i*bs
			c.Decrypt(block[off:], ciphered[off:])
			for j := range bs {
				block[off+j] ^= bout[j] ^ key[32+j%(len(key)-32)]
			}
			copy(bout, ciphered[off:])
		}
		parts = append(parts, string(block[1:block[0]+1]))
	}
	return filepath.Clean("/"+strings.Join(parts, "/")), nil
}

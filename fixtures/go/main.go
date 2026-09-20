package main

import (
	"bytes"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha256"
)

func weak(key []byte) {
	_, _ = des.NewCipher(key)
}

func verify(k, m, sig []byte) bool {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	return bytes.Equal(mac.Sum(nil), sig)
}

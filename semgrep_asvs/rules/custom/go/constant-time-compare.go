package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func verify(k, m, sig []byte, hexsig string) bool {
	mac := hmac.New(sha256.New, k)
	mac.Write(m)
	// ruleid: constant-time-compare
	if bytes.Equal(mac.Sum(nil), sig) {
		return true
	}
	// ruleid: constant-time-compare
	if hex.EncodeToString(mac.Sum(nil)) == hexsig {
		return true
	}
	// ok: constant-time-compare
	return hmac.Equal(mac.Sum(nil), sig)
}

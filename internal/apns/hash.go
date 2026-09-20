package apns

import "crypto/sha256"

func sha256Sum(value []byte) []byte { sum := sha256.Sum256(value); return sum[:] }

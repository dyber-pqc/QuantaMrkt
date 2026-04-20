package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/md5"
)

func main() {
    _, _ = rsa.GenerateKey(rand.Reader, 2048)
    _, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    _ = md5.New()
}

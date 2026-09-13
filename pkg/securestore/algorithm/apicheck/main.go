//go:build ignore
// +build ignore

package main

import (
	"crypto/sha256"
	"fmt"
	"reflect"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

func main() {
	// PrivKeyFromBytes
	{
		priv, pub := btcec.PrivKeyFromBytes(make([]byte, 32))
		fmt.Printf("PrivKeyFromBytes: priv=%T, pub=%T\n", priv, pub)
	}

	// NewPrivateKey
	{
		priv, err := btcec.NewPrivateKey()
		if err != nil {
			panic(err)
		}
		fmt.Printf("NewPrivateKey: priv=%T\n", priv)
		fmt.Printf("priv has ToECDSA: %v\n", hasMethod(priv, "ToECDSA"))
		fmt.Printf("priv has Serialize: %v\n", hasMethod(priv, "Serialize"))
		fmt.Printf("priv has PubKey: %v\n", hasMethod(priv, "PubKey"))
		fmt.Printf("priv has PrivKey: %v\n", hasMethod(priv, "PrivKey"))

		// Test Sign
		msg := []byte("test")
		h := sha256.Sum256(msg)
		sig := ecdsa.Sign(priv, h[:])
		fmt.Printf("Sign: sig=%T\n", sig)
		sigBytes := sig.Serialize()
		fmt.Printf("sig.Serialize len: %d\n", len(sigBytes))

		// Test ParseDERSignature
		sig2, err := ecdsa.ParseDERSignature(sigBytes)
		if err != nil {
			panic(err)
		}
		fmt.Printf("ParseDERSignature: sig=%T\n", sig2)

		// Test Verify
		pub := priv.PubKey()
		ok := sig2.Verify(h[:], pub)
		fmt.Printf("Verify: %v\n", ok)

		// Test ToECDSA
		ecdsaPriv := priv.ToECDSA()
		fmt.Printf("ToECDSA: %T\n", ecdsaPriv)

		// Test Serialize
		serialized := priv.Serialize()
		fmt.Printf("Serialize len: %d\n", len(serialized))
	}
}

func hasMethod(v interface{}, name string) bool {
	t := reflect.TypeOf(v)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	for i := 0; i < t.NumMethod(); i++ {
		if t.Method(i).Name == name {
			return true
		}
	}
	return false
}

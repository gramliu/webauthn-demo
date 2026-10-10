package demo

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"
)

type Executor struct {
	Private *rsa.PrivateKey
	Public  string
	KeyID   string
}

func NewExecutor(encoded string, development bool) (*Executor, error) {
	var key *rsa.PrivateKey
	if encoded == "" {
		if !development {
			return nil, errors.New("EXECUTOR_PRIVATE_KEY is required")
		}
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		key = k
	} else {
		b, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errors.New("invalid executor key encoding")
		}
		k, err := x509.ParsePKCS8PrivateKey(b)
		if err != nil {
			return nil, errors.New("invalid executor key")
		}
		var ok bool
		key, ok = k.(*rsa.PrivateKey)
		if !ok || key.N.BitLen() < 2048 {
			return nil, errors.New("executor key must be RSA, at least 2048 bits")
		}
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(der)
	return &Executor{key, encoding.EncodeToString(der), encoding.EncodeToString(hash[:16])}, nil
}
func itemAAD(aid string, item *Item) []byte {
	return []byte("credential:" + aid + ":" + item.ID + ":1")
}
func (e *Executor) decrypt(aid string, item *Item, g *Grant) (map[string]string, error) {
	delegated, err := encoding.DecodeString(g.DelegatedKey)
	if err != nil {
		return nil, bad("Invalid delegated key")
	}
	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, e.Private, delegated, []byte(g.ApprovalID))
	if err != nil || len(key) != 32 {
		return nil, bad("Could not decrypt the delegated credential key")
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := encoding.DecodeString(item.Data.Nonce)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, bad("Invalid ciphertext")
	}
	encrypted, err := encoding.DecodeString(item.Data.Ciphertext)
	if err != nil {
		return nil, bad("Invalid ciphertext")
	}
	plain, err := gcm.Open(nil, nonce, encrypted, itemAAD(aid, item))
	if err != nil {
		return nil, bad("Credential integrity check failed")
	}
	defer clear(plain)
	var secret map[string]string
	if err = json.Unmarshal(plain, &secret); err != nil {
		return nil, bad("Invalid credential contents")
	}
	if len(secret["username"]) == 0 || len(secret["password"]) == 0 {
		return nil, bad("Credential must contain a username and password")
	}
	return secret, nil
}
func (e *Executor) execute(a *Account, g *Grant, now time.Time) (string, error) {
	item := a.item(g.ItemID)
	if !g.allows(item, now, e.KeyID) {
		return "", forbidden("This grant is expired, revoked, or does not cover the operation")
	}
	secret, err := e.decrypt(a.ID, item, g)
	if err != nil {
		return "", err
	}
	// This intentionally local mock service accepts any non-empty demo login.
	// No external URL or model ever receives the password. Replace only this
	// allowlisted tool when adding a real integration.
	result := "Signed in as " + secret["username"] + ". Personal plan · 3 saved projects."
	delete(secret, "password")
	g.Uses++
	a.event("credential_used", g.Label+" · read demo profile")
	return result, nil
}

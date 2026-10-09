package demo

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/joho/godotenv"
)

func TestGrantChecksEveryBoundary(t *testing.T) {
	now := time.Now()
	item := &Item{ID: "item", Version: 1}
	baseline := Grant{ItemID: item.ID, ItemVersion: 1, Agent: "personal-agent", Operation: "read-demo-profile", Destination: "demo-service", KeyID: "key", ExpiresAt: now.Add(time.Hour)}
	tests := []struct {
		name    string
		mutate  func(*Grant)
		allowed bool
	}{
		{"active", func(g *Grant) {}, true},
		{"expired", func(g *Grant) { g.ExpiresAt = now.Add(-time.Second) }, false},
		{"expiry boundary", func(g *Grant) { g.ExpiresAt = now }, false},
		{"revoked", func(g *Grant) { g.RevokedAt = &now }, false},
		{"different item", func(g *Grant) { g.ItemID = "another" }, false},
		{"old credential version", func(g *Grant) { g.ItemVersion = 0 }, false},
		{"different agent", func(g *Grant) { g.Agent = "other-agent" }, false},
		{"different operation", func(g *Grant) { g.Operation = "export-password" }, false},
		{"external destination", func(g *Grant) { g.Destination = "https://attacker.test" }, false},
		{"old executor key", func(g *Grant) { g.KeyID = "old-key" }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := baseline
			tc.mutate(&g)
			if got := g.allows(item, now, "key"); got != tc.allowed {
				t.Fatalf("allowed=%v", got)
			}
		})
	}
	if baseline.allows(nil, now, "key") {
		t.Fatal("missing item accepted")
	}
}

func fixture(t *testing.T) (*Executor, *Account, *Grant) {
	t.Helper()
	executor, err := NewExecutor("", true)
	if err != nil {
		t.Fatal(err)
	}
	account := &Account{ID: "account", Name: "test"}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	_, _ = rand.Read(nonce)
	item := Item{ID: "item", Version: 1, Label: "Demo"}
	plain := []byte(`{"username":"test@example.test","password":"NEVER-IN-CHAT"}`)
	item.Data = Box{encoding.EncodeToString(nonce), encoding.EncodeToString(gcm.Seal(nil, nonce, plain, itemAAD(account.ID, &item)))}
	delegated, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &executor.Private.PublicKey, key, []byte("approval"))
	if err != nil {
		t.Fatal(err)
	}
	account.Items = []Item{item}
	grant := &Grant{ID: "grant", ApprovalID: "approval", ItemID: item.ID, ItemVersion: 1, Label: item.Label, Agent: "personal-agent", Operation: "read-demo-profile", Destination: "demo-service", KeyID: executor.KeyID, DelegatedKey: encoding.EncodeToString(delegated), ExpiresAt: time.Now().Add(time.Hour)}
	return executor, account, grant
}

func TestExecutorUsesCredentialWithoutReturningPassword(t *testing.T) {
	e, a, g := fixture(t)
	result, err := e.execute(a, g, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(result, "NEVER-IN-CHAT") || !strings.Contains(result, "test@example.test") {
		t.Fatal("unsafe result")
	}
	if g.Uses != 1 || len(a.Events) != 1 {
		t.Fatal("credential use was not audited")
	}
}
func TestExecutorRejectsTamperingAndCrossAccountCiphertext(t *testing.T) {
	e, a, g := fixture(t)
	original := a.Items[0].Data.Ciphertext
	ciphertext, _ := encoding.DecodeString(original)
	ciphertext[0] ^= 1
	a.Items[0].Data.Ciphertext = encoding.EncodeToString(ciphertext)
	if _, err := e.execute(a, g, time.Now()); err == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	a.Items[0].Data.Ciphertext = original
	a.ID = "other-account"
	if _, err := e.execute(a, g, time.Now()); err == nil {
		t.Fatal("cross-account ciphertext accepted")
	}
	a.ID = "account"
	g.ApprovalID = "another-request"
	if _, err := e.execute(a, g, time.Now()); err == nil {
		t.Fatal("delegation reused for a different request")
	}
	if g.Uses != 0 {
		t.Fatal("failed execution counted as use")
	}
}
func TestPublicStateOmitsDelegationAndPasskeyRecords(t *testing.T) {
	e, a, g := fixture(t)
	a.Grants = []Grant{*g}
	a.Credentials = []webauthn.Credential{{ID: []byte("private-record")}}
	b, err := json.Marshal(a.public(e.KeyID))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"delegatedKey", g.DelegatedKey, "credentials", "private-record"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("public state leaked %s", forbidden)
		}
	}
	if strings.Contains(string(b), "NEVER-IN-CHAT") {
		t.Fatal("public state leaked plaintext")
	}
}
func TestAPIRejectsUntrustedMutationAndUnauthenticatedRead(t *testing.T) {
	e, _, _ := fixture(t)
	s, err := NewServer(&Store{}, e, "http://localhost:5173")
	if err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"", "https://attacker.test"} {
		r := httptest.NewRequest("POST", "/api/auth/register/options", strings.NewReader(`{"name":"test"}`))
		r.Header.Set("Origin", origin)
		r.Header.Set("X-Vault-Request", "1")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("untrusted origin %q accepted", origin)
		}
	}
	r := httptest.NewRequest("GET", "/api/state", nil)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("unauthenticated state exposed")
	}
}

func dbStore(t *testing.T) *Store {
	t.Helper()
	if os.Getenv("RUN_DB_TESTS") != "1" {
		t.Skip("set RUN_DB_TESTS=1 to test Postgres persistence")
	}
	_ = godotenv.Load("../../../.env.local")
	ctx := context.Background()
	s, err := NewStore(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal("database connection failed")
	}
	t.Cleanup(s.Pool.Close)
	s.Origin = "http://test-" + randomID() + ".test"
	return s
}
func dbAccount(t *testing.T, s *Store) *Account {
	t.Helper()
	a := &Account{ID: randomID(), Name: "integration-test", PRFSalt: randomID()}
	if err := s.Create(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.Pool.Exec(context.Background(), "DELETE FROM demo_accounts WHERE id=$1", a.ID) })
	return a
}
func TestPostgresChallengeBindingExpiryAndReplay(t *testing.T) {
	s := dbStore(t)
	a := dbAccount(t, s)
	ctx := context.Background()
	token, err := s.Ceremony(ctx, a.ID, "approve", "request", &webauthn.SessionData{Challenge: "nonce", Expires: time.Now().Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Consume(ctx, token, "login", ""); err == nil {
		t.Fatal("approval challenge accepted for login")
	}
	if _, _, err = s.Consume(ctx, token, "approve", "other-request"); err == nil {
		t.Fatal("challenge accepted for another approval")
	}
	id, sd, err := s.Consume(ctx, token, "approve", "request")
	if err != nil || id != a.ID || sd.Challenge != "nonce" {
		t.Fatal("valid challenge failed")
	}
	if _, _, err = s.Consume(ctx, token, "approve", "request"); err == nil {
		t.Fatal("replayed challenge accepted")
	}
	token, err = s.Ceremony(ctx, a.ID, "login", "", sd)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Pool.Exec(ctx, "UPDATE demo_ceremonies SET expires_at=now()-interval '1 second' WHERE token_hash=$1", tokenHash(token))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.Consume(ctx, token, "login", ""); err == nil {
		t.Fatal("expired challenge accepted")
	}
}
func TestPostgresAtomicUpdatesAndOriginIsolation(t *testing.T) {
	s := dbStore(t)
	a := dbAccount(t, s)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Update(ctx, a.ID, func(a *Account) error { a.message("user", "atomic update", ""); return nil })
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	reloaded, err := s.ByID(ctx, a.ID)
	if err != nil || len(reloaded.Messages) != 8 {
		t.Fatal("concurrent updates lost data")
	}
	other := &Store{Pool: s.Pool, Origin: "https://other-origin.test"}
	if _, err = other.ByName(ctx, a.Name); err == nil {
		t.Fatal("account crossed origin namespace")
	}
	if _, err = other.Update(ctx, a.ID, func(*Account) error { return nil }); err == nil {
		t.Fatal("account mutation crossed origin namespace")
	}
}

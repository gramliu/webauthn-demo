package demo

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

var encoding = base64.RawURLEncoding

type Box struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type Item struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	Version    int       `json:"version"`
	Data       Box       `json:"data"`
	WrappedKey Box       `json:"wrappedKey"`
	CreatedAt  time.Time `json:"createdAt"`
}

type Approval struct {
	ID           string    `json:"id"`
	ItemID       string    `json:"itemId"`
	ItemVersion  int       `json:"itemVersion"`
	Label        string    `json:"label"`
	Agent        string    `json:"agent"`
	Operation    string    `json:"operation"`
	Destination  string    `json:"destination"`
	LeaseSeconds int       `json:"leaseSeconds"`
	KeyID        string    `json:"keyId"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"createdAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

type Grant struct {
	ID           string     `json:"id"`
	ApprovalID   string     `json:"approvalId"`
	ItemID       string     `json:"itemId"`
	ItemVersion  int        `json:"itemVersion"`
	Label        string     `json:"label"`
	Agent        string     `json:"agent"`
	Operation    string     `json:"operation"`
	Destination  string     `json:"destination"`
	KeyID        string     `json:"keyId"`
	DelegatedKey string     `json:"delegatedKey"`
	ApprovedAt   time.Time  `json:"approvedAt"`
	ExpiresAt    time.Time  `json:"expiresAt"`
	RevokedAt    *time.Time `json:"revokedAt,omitempty"`
	Uses         int        `json:"uses"`
}

type Event struct {
	ID     string    `json:"id"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
	At     time.Time `json:"at"`
}

type Message struct {
	ID         string    `json:"id"`
	Role       string    `json:"role"`
	Text       string    `json:"text"`
	ApprovalID string    `json:"approvalId,omitempty"`
	At         time.Time `json:"at"`
}

// Account is a transactionally locked aggregate for this small demo. The browser
// owns all vault encryption. Only individually delegated item keys enter Go.
type Account struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Origin      string                `json:"origin"`
	PRFSalt     string                `json:"prfSalt"`
	Credentials []webauthn.Credential `json:"credentials"`
	VaultKey    *Box                  `json:"vaultKey,omitempty"`
	RecoveryKey *Box                  `json:"recoveryKey,omitempty"`
	Items       []Item                `json:"items"`
	Approvals   []Approval            `json:"approvals"`
	Grants      []Grant               `json:"grants"`
	Events      []Event               `json:"events"`
	Messages    []Message             `json:"messages"`
}

func (a *Account) WebAuthnID() []byte                         { return []byte(a.ID) }
func (a *Account) WebAuthnName() string                       { return a.Name }
func (a *Account) WebAuthnDisplayName() string                { return a.Name }
func (a *Account) WebAuthnCredentials() []webauthn.Credential { return a.Credentials }

func randomID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return encoding.EncodeToString(b)
}
func tokenHash(s string) string { h := sha256.Sum256([]byte(s)); return encoding.EncodeToString(h[:]) }
func (a *Account) event(kind, detail string) {
	a.Events = append(a.Events, Event{randomID(), kind, detail, time.Now().UTC()})
	if len(a.Events) > 100 {
		a.Events = a.Events[len(a.Events)-100:]
	}
}
func (a *Account) message(role, text, approval string) {
	a.Messages = append(a.Messages, Message{randomID(), role, text, approval, time.Now().UTC()})
	if len(a.Messages) > 100 {
		a.Messages = a.Messages[len(a.Messages)-100:]
	}
}
func (a *Account) item(id string) *Item {
	for i := range a.Items {
		if a.Items[i].ID == id {
			return &a.Items[i]
		}
	}
	return nil
}
func (a *Account) approval(id string) *Approval {
	for i := range a.Approvals {
		if a.Approvals[i].ID == id {
			return &a.Approvals[i]
		}
	}
	return nil
}
func (g *Grant) allows(item *Item, now time.Time, keyID string) bool {
	return item != nil && g.RevokedAt == nil && now.Before(g.ExpiresAt) &&
		g.ItemID == item.ID && g.ItemVersion == item.Version && g.KeyID == keyID &&
		g.Agent == "personal-agent" && g.Operation == "read-demo-profile" && g.Destination == "demo-service"
}
func (a *Account) public(keyID string) map[string]any {
	grants := make([]map[string]any, 0, len(a.Grants))
	for _, g := range a.Grants {
		grants = append(grants, map[string]any{"id": g.ID, "approvalId": g.ApprovalID, "itemId": g.ItemID, "label": g.Label, "approvedAt": g.ApprovedAt, "expiresAt": g.ExpiresAt, "revokedAt": g.RevokedAt, "uses": g.Uses, "active": g.allows(a.item(g.ItemID), time.Now(), keyID)})
	}
	return map[string]any{"id": a.ID, "name": a.Name, "prfSalt": a.PRFSalt, "vaultKey": a.VaultKey, "recoveryKey": a.RecoveryKey, "items": a.Items, "approvals": a.Approvals, "grants": grants, "events": a.Events, "messages": a.Messages}
}

type problem struct {
	Status  int
	Message string
}

func (p problem) Error() string { return p.Message }
func bad(s string) error        { return problem{400, s} }
func forbidden(s string) error  { return problem{403, s} }

var errNotFound = problem{404, "Not found"}

func validateBox(b Box, max int) error {
	n, e := encoding.DecodeString(b.Nonce)
	if e != nil || len(n) != 12 {
		return bad("Invalid encryption nonce")
	}
	c, e := encoding.DecodeString(b.Ciphertext)
	if e != nil || len(c) < 16 || len(c) > max {
		return bad("Invalid ciphertext")
	}
	return nil
}
func parseJSON(data []byte, v any) error {
	if len(data) == 0 {
		return errors.New("empty data")
	}
	return json.Unmarshal(data, v)
}

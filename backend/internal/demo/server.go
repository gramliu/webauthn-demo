package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Server struct {
	Store    *Store
	Executor *Executor
	Auth     *webauthn.WebAuthn
	Origin   string
	Secure   bool
}
type handler func(http.ResponseWriter, *http.Request) error
type proof struct {
	Token        string          `json:"token"`
	Credential   json.RawMessage `json:"credential"`
	DelegatedKey string          `json:"delegatedKey,omitempty"`
}

func NewServer(store *Store, executor *Executor, origin string) (*Server, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || u.Path != "" || u.RawQuery != "" || !(u.Scheme == "https" || (u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) {
		return nil, errors.New("APP_ORIGIN must be HTTPS or localhost")
	}
	auth, err := webauthn.New(&webauthn.Config{RPDisplayName: "Keyhold · Personal Agent Vault", RPID: u.Hostname(), RPOrigins: []string{origin}, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}})
	if err != nil {
		return nil, err
	}
	store.Origin = origin
	return &Server{store, executor, auth, origin, u.Scheme == "https"}, nil
}
func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return bad("Invalid request body")
	}
	return nil
}
func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Header.Get("Origin") != s.Origin || r.Header.Get("X-Vault-Request") != "1" {
				respond(w, 403, map[string]string{"error": "Request origin rejected"})
				return
			}
		}
		if err := h(w, r); err != nil {
			var p problem
			if errors.As(err, &p) {
				respond(w, p.Status, map[string]string{"error": p.Message})
			} else {
				respond(w, 500, map[string]string{"error": "The server could not complete this request. Try again."})
			}
		}
	}
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.wrap(func(w http.ResponseWriter, r *http.Request) error {
		if err := s.Store.Pool.Ping(r.Context()); err != nil {
			return err
		}
		respond(w, 200, map[string]any{"status": "ok", "storage": "postgres", "agent": "scripted-demo", "origin": s.Origin})
		return nil
	}))
	mux.HandleFunc("GET /api/state", s.wrap(s.state))
	mux.HandleFunc("POST /api/auth/register/options", s.wrap(s.registerOptions))
	mux.HandleFunc("POST /api/auth/register/verify", s.wrap(s.registerVerify))
	mux.HandleFunc("POST /api/auth/login/options", s.wrap(s.loginOptions))
	mux.HandleFunc("POST /api/auth/login/verify", s.wrap(s.loginVerify))
	mux.HandleFunc("POST /api/auth/logout", s.wrap(s.logout))
	mux.HandleFunc("POST /api/vault/init", s.wrap(s.initVault))
	mux.HandleFunc("POST /api/vault/items", s.wrap(s.addItem))
	mux.HandleFunc("POST /api/chat/messages", s.wrap(s.chat))
	mux.HandleFunc("GET /api/approvals/{id}", s.wrap(s.getApproval))
	mux.HandleFunc("POST /api/approvals/{id}/options", s.wrap(s.approvalOptions))
	mux.HandleFunc("POST /api/approvals/{id}/approve", s.wrap(s.approve))
	mux.HandleFunc("POST /api/approvals/{id}/deny", s.wrap(s.deny))
	mux.HandleFunc("POST /api/grants/{id}/revoke", s.wrap(s.revoke))
	mux.HandleFunc("POST /api/approvals/{id}/resume", s.wrap(s.resume))
	return mux
}
func (s *Server) account(r *http.Request) (*Account, error) {
	cookie, err := r.Cookie("vault_session")
	if err != nil {
		return nil, problem{401, "Sign in with your passkey"}
	}
	id, err := s.Store.Session(r.Context(), cookie.Value)
	if err != nil {
		return nil, err
	}
	return s.Store.ByID(r.Context(), id)
}
func (s *Server) cookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: "vault_session", Value: token, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}
func (s *Server) signIn(ctx context.Context, w http.ResponseWriter, a *Account) error {
	token, err := s.Store.NewSession(ctx, a.ID)
	if err != nil {
		return err
	}
	s.cookie(w, token, 7*24*3600)
	respond(w, 200, a.public(s.Executor.KeyID))
	return nil
}
func (s *Server) state(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	respond(w, 200, a.public(s.Executor.KeyID))
	return nil
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request) error {
	if c, err := r.Cookie("vault_session"); err == nil {
		_, err = s.Store.Pool.Exec(r.Context(), "DELETE FROM demo_sessions WHERE token_hash=$1", tokenHash(c.Value))
		if err != nil {
			return err
		}
	}
	s.cookie(w, "", -1)
	respond(w, 200, map[string]bool{"ok": true})
	return nil
}

var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,31}$`)

func (s *Server) authName(w http.ResponseWriter, r *http.Request) (string, error) {
	var in struct {
		Name string `json:"name"`
	}
	if err := decode(w, r, &in); err != nil {
		return "", err
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	if !namePattern.MatchString(in.Name) {
		return "", bad("Use 3–32 letters, numbers, underscores, or dashes")
	}
	ok, err := s.Store.RateLimit(r.Context(), "auth:"+in.Name)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", problem{429, "Too many attempts. Try again in a minute."}
	}
	return in.Name, nil
}
func (s *Server) registerOptions(w http.ResponseWriter, r *http.Request) error {
	name, err := s.authName(w, r)
	if err != nil {
		return err
	}
	a, err := s.Store.ByName(r.Context(), name)
	if errors.Is(err, errNotFound) {
		a = &Account{ID: randomID(), Name: name, PRFSalt: randomID(), Items: []Item{}, Approvals: []Approval{}, Grants: []Grant{}, Events: []Event{}, Messages: []Message{}}
		if err = s.Store.Create(r.Context(), a); err != nil {
			return problem{409, "This account name is in use. Try signing in."}
		}
	} else if err != nil {
		return err
	}
	if len(a.Credentials) > 0 {
		return problem{409, "This account already has a passkey. Sign in instead."}
	}
	options, session, err := s.Auth.BeginRegistration(a, webauthn.WithExtensions(webauthn.WithExtensionPRFSupport()))
	if err != nil {
		return err
	}
	token, err := s.Store.Ceremony(r.Context(), a.ID, "register", "", session)
	if err != nil {
		return err
	}
	respond(w, 200, map[string]any{"token": token, "publicKey": options.Response, "salt": a.PRFSalt})
	return nil
}
func credentialRequest(r *http.Request, data []byte) *http.Request {
	req := r.Clone(r.Context())
	req.Body = http.NoBody
	if len(data) > 0 {
		req.Body = ioBody(data)
	}
	return req
}
func ioBody(data []byte) *bodyReader { return &bodyReader{bytes.NewReader(data)} }

type bodyReader struct{ *bytes.Reader }

func (*bodyReader) Close() error { return nil }
func (s *Server) registerVerify(w http.ResponseWriter, r *http.Request) error {
	var in proof
	if err := decode(w, r, &in); err != nil {
		return err
	}
	id, sd, err := s.Store.Consume(r.Context(), in.Token, "register", "")
	if err != nil {
		return err
	}
	a, err := s.Store.Update(r.Context(), id, func(a *Account) error {
		if len(a.Credentials) > 0 {
			return forbidden("Account already registered")
		}
		c, e := s.Auth.FinishRegistration(a, *sd, credentialRequest(r, in.Credential))
		if e != nil {
			return bad("Passkey registration could not be verified")
		}
		a.Credentials = append(a.Credentials, *c)
		a.event("account_created", "Passkey registered")
		return nil
	})
	if err != nil {
		return err
	}
	return s.signIn(r.Context(), w, a)
}
func (s *Server) beginLogin(w http.ResponseWriter, r *http.Request, a *Account, purpose, approval string) error {
	salt, _ := encoding.DecodeString(a.PRFSalt)
	options, session, err := s.Auth.BeginLogin(a, webauthn.WithUserVerification(protocol.VerificationRequired), webauthn.WithAssertionExtensions(webauthn.WithExtensionPRF(protocol.PRFValues{First: salt})))
	if err != nil {
		return err
	}
	token, err := s.Store.Ceremony(r.Context(), a.ID, purpose, approval, session)
	if err != nil {
		return err
	}
	respond(w, 200, map[string]any{"token": token, "publicKey": options.Response, "salt": a.PRFSalt})
	return nil
}
func (s *Server) loginOptions(w http.ResponseWriter, r *http.Request) error {
	name, err := s.authName(w, r)
	if err != nil {
		return err
	}
	a, err := s.Store.ByName(r.Context(), name)
	if err != nil {
		return problem{404, "No account found. Create a passkey first."}
	}
	if len(a.Credentials) == 0 {
		return bad("Finish registering this account first")
	}
	return s.beginLogin(w, r, a, "login", "")
}
func (s *Server) verifyLogin(a *Account, sd *webauthn.SessionData, r *http.Request, data []byte) error {
	c, err := s.Auth.FinishLogin(a, *sd, credentialRequest(r, data))
	if err != nil {
		return bad("Passkey verification failed. Try again.")
	}
	for i := range a.Credentials {
		if bytes.Equal(a.Credentials[i].ID, c.ID) {
			a.Credentials[i] = *c
			return nil
		}
	}
	return forbidden("Passkey does not belong to this account")
}
func (s *Server) loginVerify(w http.ResponseWriter, r *http.Request) error {
	var in proof
	if err := decode(w, r, &in); err != nil {
		return err
	}
	id, sd, err := s.Store.Consume(r.Context(), in.Token, "login", "")
	if err != nil {
		return err
	}
	a, err := s.Store.Update(r.Context(), id, func(a *Account) error {
		if err := s.verifyLogin(a, sd, r, in.Credential); err != nil {
			return err
		}
		a.event("signed_in", "Verified with passkey")
		return nil
	})
	if err != nil {
		return err
	}
	return s.signIn(r.Context(), w, a)
}
func (s *Server) initVault(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	var in struct {
		VaultKey    Box `json:"vaultKey"`
		RecoveryKey Box `json:"recoveryKey"`
	}
	if err = decode(w, r, &in); err != nil {
		return err
	}
	if err = validateBox(in.VaultKey, 48); err != nil {
		return err
	}
	if err = validateBox(in.RecoveryKey, 48); err != nil {
		return err
	}
	a, err = s.Store.Update(r.Context(), a.ID, func(a *Account) error {
		if a.VaultKey != nil {
			return problem{409, "Vault is already initialized"}
		}
		a.VaultKey = &in.VaultKey
		a.RecoveryKey = &in.RecoveryKey
		a.event("vault_created", "Encrypted vault initialized in browser")
		return nil
	})
	if err != nil {
		return err
	}
	respond(w, 200, a.public(s.Executor.KeyID))
	return nil
}
func (s *Server) addItem(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	var item Item
	if err = decode(w, r, &item); err != nil {
		return err
	}
	id, e := encoding.DecodeString(item.ID)
	if e != nil || len(id) != 32 {
		return bad("Invalid credential ID")
	}
	item.Label = strings.TrimSpace(item.Label)
	if len(item.Label) < 1 || len(item.Label) > 80 {
		return bad("Credential label must be 1–80 characters")
	}
	if err = validateBox(item.Data, 8192); err != nil {
		return err
	}
	if err = validateBox(item.WrappedKey, 48); err != nil {
		return err
	}
	item.Version = 1
	item.CreatedAt = time.Now().UTC()
	a, err = s.Store.Update(r.Context(), a.ID, func(a *Account) error {
		if a.VaultKey == nil {
			return bad("Initialize your vault first")
		}
		if len(a.Items) >= 20 {
			return bad("Demo supports up to 20 credentials")
		}
		if a.item(item.ID) != nil {
			return problem{409, "Credential already exists"}
		}
		a.Items = append(a.Items, item)
		a.event("credential_added", item.Label)
		return nil
	})
	if err != nil {
		return err
	}
	respond(w, 201, a.public(s.Executor.KeyID))
	return nil
}
func validLease(seconds int) bool { return seconds == 60 || seconds == 3600 || seconds == 86400 }
func (s *Server) chat(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	var in struct {
		Text         string `json:"text"`
		ItemID       string `json:"itemId"`
		LeaseSeconds int    `json:"leaseSeconds"`
	}
	if err = decode(w, r, &in); err != nil {
		return err
	}
	if len(in.Text) > 2000 {
		return bad("Message is too long")
	}
	if !validLease(in.LeaseSeconds) {
		return bad("Choose a one-minute, one-hour, or 24-hour lease")
	}
	ok, e := s.Store.RateLimit(r.Context(), "chat:"+a.ID)
	if e != nil {
		return e
	}
	if !ok {
		return problem{429, "Please wait a minute before requesting another action"}
	}
	a, err = s.Store.Update(r.Context(), a.ID, func(a *Account) error {
		item := a.item(in.ItemID)
		if item == nil {
			return errNotFound
		}
		a.message("user", in.Text, "")
		for i := len(a.Grants) - 1; i >= 0; i-- {
			if a.Grants[i].ItemID == item.ID && a.Grants[i].allows(item, time.Now(), s.Executor.KeyID) {
				result, e := s.Executor.execute(a, &a.Grants[i], time.Now())
				if e != nil {
					return e
				}
				a.message("assistant", result+" Existing grant used.", "")
				return nil
			}
		}
		for i := range a.Approvals {
			p := &a.Approvals[i]
			if p.ItemID == item.ID && p.Status == "pending" && time.Now().Before(p.ExpiresAt) {
				a.message("assistant", "Approval is pending for "+item.Label+".", p.ID)
				return nil
			}
		}
		if len(a.Approvals) >= 100 {
			return bad("Demo approval limit reached")
		}
		p := Approval{ID: randomID(), ItemID: item.ID, ItemVersion: item.Version, Label: item.Label, Agent: "personal-agent", Operation: "read-demo-profile", Destination: "demo-service", LeaseSeconds: in.LeaseSeconds, KeyID: s.Executor.KeyID, Status: "pending", CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
		a.Approvals = append(a.Approvals, p)
		a.event("approval_requested", item.Label+" · read demo profile")
		a.message("assistant", "Approve access to "+item.Label+" to read your demo profile.", p.ID)
		return nil
	})
	if err != nil {
		return err
	}
	respond(w, 200, a.public(s.Executor.KeyID))
	return nil
}
func (s *Server) getApproval(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	p := a.approval(r.PathValue("id"))
	if p == nil {
		return errNotFound
	}
	respond(w, 200, map[string]any{"request": p, "publicKey": s.Executor.Public, "keyId": s.Executor.KeyID})
	return nil
}
func (s *Server) approvalOptions(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	p := a.approval(r.PathValue("id"))
	if p == nil {
		return errNotFound
	}
	if p.Status != "pending" || !time.Now().Before(p.ExpiresAt) {
		return bad("This approval request is no longer pending")
	}
	if p.KeyID != s.Executor.KeyID {
		return bad("Executor key changed. Request access again.")
	}
	return s.beginLogin(w, r, a, "approve", p.ID)
}
func (s *Server) approve(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	approvalID := r.PathValue("id")
	var in proof
	if err = decode(w, r, &in); err != nil {
		return err
	}
	id, sd, err := s.Store.Consume(r.Context(), in.Token, "approve", approvalID)
	if err != nil {
		return err
	}
	if id != a.ID {
		return forbidden("Approval belongs to another user")
	}
	a, err = s.Store.Update(r.Context(), id, func(a *Account) error {
		p := a.approval(approvalID)
		if p == nil {
			return errNotFound
		}
		if p.Status != "pending" || !time.Now().Before(p.ExpiresAt) {
			return bad("This approval request expired or was already used")
		}
		if p.KeyID != s.Executor.KeyID || !validLease(p.LeaseSeconds) {
			return bad("Approval configuration changed")
		}
		if err := s.verifyLogin(a, sd, r, in.Credential); err != nil {
			return err
		}
		item := a.item(p.ItemID)
		if item == nil || item.Version != p.ItemVersion {
			return bad("Credential version changed")
		}
		now := time.Now().UTC()
		g := Grant{ID: randomID(), ApprovalID: p.ID, ItemID: p.ItemID, ItemVersion: p.ItemVersion, Label: p.Label, Agent: p.Agent, Operation: p.Operation, Destination: p.Destination, KeyID: p.KeyID, DelegatedKey: in.DelegatedKey, ApprovedAt: now, ExpiresAt: now.Add(time.Duration(p.LeaseSeconds) * time.Second)}
		if secret, e := s.Executor.decrypt(a.ID, item, &g); e != nil {
			return e
		} else {
			clear(secret)
		}
		p.Status = "approved"
		a.Grants = append(a.Grants, g)
		a.event("grant_approved", p.Label+" · "+fmt.Sprint(p.LeaseSeconds)+" second lease")
		return nil
	})
	if err != nil {
		return err
	}
	respond(w, 200, a.public(s.Executor.KeyID))
	return nil
}
func (s *Server) deny(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	a, err = s.Store.Update(r.Context(), a.ID, func(a *Account) error {
		p := a.approval(r.PathValue("id"))
		if p == nil {
			return errNotFound
		}
		if p.Status != "pending" {
			return bad("Request is no longer pending")
		}
		p.Status = "denied"
		a.event("approval_denied", p.Label)
		a.message("assistant", "Access denied.", "")
		return nil
	})
	if err != nil {
		return err
	}
	respond(w, 200, a.public(s.Executor.KeyID))
	return nil
}
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	a, err = s.Store.Update(r.Context(), a.ID, func(a *Account) error {
		for i := range a.Grants {
			g := &a.Grants[i]
			if g.ID == r.PathValue("id") {
				now := time.Now().UTC()
				g.RevokedAt = &now
				g.DelegatedKey = ""
				a.event("grant_revoked", g.Label)
				return nil
			}
		}
		return errNotFound
	})
	if err != nil {
		return err
	}
	respond(w, 200, a.public(s.Executor.KeyID))
	return nil
}
func (s *Server) resume(w http.ResponseWriter, r *http.Request) error {
	a, err := s.account(r)
	if err != nil {
		return err
	}
	a, err = s.Store.Update(r.Context(), a.ID, func(a *Account) error {
		p := a.approval(r.PathValue("id"))
		if p == nil {
			return errNotFound
		}
		if p.Status == "completed" {
			return nil
		}
		if p.Status != "approved" {
			return bad("Approve access before resuming")
		}
		for i := range a.Grants {
			g := &a.Grants[i]
			if g.ApprovalID == p.ID {
				result, e := s.Executor.execute(a, g, time.Now())
				if e != nil {
					return e
				}
				p.Status = "completed"
				a.message("assistant", result, "")
				return nil
			}
		}
		return forbidden("No active grant for this action")
	})
	if err != nil {
		return err
	}
	respond(w, 200, a.public(s.Executor.KeyID))
	return nil
}

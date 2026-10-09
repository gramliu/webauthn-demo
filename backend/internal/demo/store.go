package demo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const Schema = `
CREATE TABLE IF NOT EXISTS demo_accounts (id text PRIMARY KEY, name text NOT NULL, origin text NOT NULL, data jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(name,origin));
CREATE TABLE IF NOT EXISTS demo_sessions (token_hash text PRIMARY KEY, account_id text NOT NULL REFERENCES demo_accounts(id) ON DELETE CASCADE, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS demo_ceremonies (token_hash text PRIMARY KEY, account_id text NOT NULL REFERENCES demo_accounts(id) ON DELETE CASCADE, purpose text NOT NULL, approval_id text NOT NULL DEFAULT '', data jsonb NOT NULL, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS demo_limits (key text PRIMARY KEY, bucket_start timestamptz NOT NULL, count integer NOT NULL);
CREATE INDEX IF NOT EXISTS demo_session_expiry ON demo_sessions(expires_at);
CREATE INDEX IF NOT EXISTS demo_ceremony_expiry ON demo_ceremonies(expires_at);
`

type Store struct {
	Pool   *pgxpool.Pool
	Origin string
}

func NewStore(ctx context.Context, url string) (*Store, error) {
	c, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	c.MaxConns = 4
	c.MinConns = 0
	c.MaxConnIdleTime = time.Minute
	p, err := pgxpool.NewWithConfig(ctx, c)
	if err != nil {
		return nil, err
	}
	if err = p.Ping(ctx); err != nil {
		p.Close()
		return nil, err
	}
	return &Store{Pool: p}, nil
}
func (s *Store) Migrate(ctx context.Context) error { _, e := s.Pool.Exec(ctx, Schema); return e }
func (s *Store) ByName(ctx context.Context, name string) (*Account, error) {
	return s.load(ctx, "name", name)
}
func (s *Store) ByID(ctx context.Context, id string) (*Account, error) { return s.load(ctx, "id", id) }
func (s *Store) load(ctx context.Context, column, value string) (*Account, error) {
	var data []byte
	err := s.Pool.QueryRow(ctx, "SELECT data FROM demo_accounts WHERE "+column+"=$1 AND origin=$2", value, s.Origin).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	var a Account
	err = json.Unmarshal(data, &a)
	return &a, err
}
func (s *Store) Create(ctx context.Context, a *Account) error {
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	a.Origin = s.Origin
	b, err = json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, "INSERT INTO demo_accounts(id,name,origin,data) VALUES($1,$2,$3,$4)", a.ID, a.Name, s.Origin, b)
	return err
}
func (s *Store) Update(ctx context.Context, id string, fn func(*Account) error) (*Account, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var data []byte
	err = tx.QueryRow(ctx, "SELECT data FROM demo_accounts WHERE id=$1 AND origin=$2 FOR UPDATE", id, s.Origin).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	var a Account
	if err = json.Unmarshal(data, &a); err != nil {
		return nil, err
	}
	if err = fn(&a); err != nil {
		return nil, err
	}
	data, err = json.Marshal(a)
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, "UPDATE demo_accounts SET data=$2 WHERE id=$1", id, data); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &a, nil
}
func (s *Store) Session(ctx context.Context, token string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, "SELECT account_id FROM demo_sessions WHERE token_hash=$1 AND expires_at>now()", tokenHash(token)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", problem{401, "Sign in with your passkey"}
	}
	return id, err
}
func (s *Store) NewSession(ctx context.Context, id string) (string, error) {
	token := randomID()
	_, err := s.Pool.Exec(ctx, "INSERT INTO demo_sessions VALUES($1,$2,$3)", tokenHash(token), id, time.Now().Add(7*24*time.Hour))
	return token, err
}
func (s *Store) Ceremony(ctx context.Context, id, purpose, approval string, session *webauthn.SessionData) (string, error) {
	token := randomID()
	b, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	_, err = s.Pool.Exec(ctx, "INSERT INTO demo_ceremonies VALUES($1,$2,$3,$4,$5,$6)", tokenHash(token), id, purpose, approval, b, time.Now().Add(5*time.Minute))
	return token, err
}
func (s *Store) Consume(ctx context.Context, token, purpose, approval string) (string, *webauthn.SessionData, error) {
	var id string
	var data []byte
	err := s.Pool.QueryRow(ctx, "DELETE FROM demo_ceremonies WHERE token_hash=$1 AND purpose=$2 AND approval_id=$3 AND expires_at>now() RETURNING account_id,data", tokenHash(token), purpose, approval).Scan(&id, &data)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, bad("This passkey challenge expired or was already used. Try again.")
	}
	if err != nil {
		return "", nil, err
	}
	var sd webauthn.SessionData
	err = json.Unmarshal(data, &sd)
	return id, &sd, err
}
func (s *Store) RateLimit(ctx context.Context, key string) (bool, error) {
	var count int
	err := s.Pool.QueryRow(ctx, `INSERT INTO demo_limits(key,bucket_start,count) VALUES($1,date_trunc('minute',now()),1)
 ON CONFLICT(key) DO UPDATE SET count=CASE WHEN demo_limits.bucket_start=date_trunc('minute',now()) THEN demo_limits.count+1 ELSE 1 END,bucket_start=date_trunc('minute',now()) RETURNING count`, tokenHash(key)).Scan(&count)
	return count <= 40, err
}

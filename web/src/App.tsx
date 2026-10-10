import { useCallback, useEffect, useRef, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { ArrowDownToLine, ArrowLeft, ArrowRight, Check, ChevronRight, Clock3, Fingerprint, KeyRound, LockKeyhole, LogOut, MessageSquare, Plus, Send, ShieldCheck, Sparkles, X } from 'lucide-react';
import { api, APIError } from './api';
import { aes, b64, delegate, derive, encryptItem, open, random, seal, unb64, vaultAAD } from './crypto';
import { authenticate, createPasskey } from './webauthn';
import type { ApprovalDetail, Ceremony, State } from './types';

type Page = 'chat' | 'vault' | 'activity' | 'approval';
function route() {
  const match = location.pathname.match(/^\/approve\/([^/]+)$/);
  return { page: (match ? 'approval' : location.pathname === '/vault' ? 'vault' : location.pathname === '/activity' ? 'activity' : 'chat') as Page, id: match?.[1] || '' };
}
function time(value: string) { return new Date(value).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }); }
function duration(seconds: number) { return seconds === 86400 ? '24 hours' : seconds === 3600 ? '1 hour' : '1 minute'; }
function remaining(expiry: string) {
  const minutes = Math.ceil((new Date(expiry).getTime() - Date.now()) / 60000);
  return minutes <= 0 ? 'Expired' : minutes >= 60 ? `${Math.floor(minutes / 60)}h ${minutes % 60}m left` : `${minutes}m left`;
}
function Modal({ title, children, close }: { title: string; children: ReactNode; close: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { ref.current?.showModal(); }, []);
  return <dialog ref={ref} className="modal" onCancel={close} aria-labelledby="modal-title">
    <div className="modal-heading"><h2 id="modal-title">{title}</h2><button className="icon-button" aria-label="Close dialog" onClick={close}><X size={20} /></button></div>{children}
  </dialog>;
}

export default function App() {
  const [state, setState] = useState<State | null>(null);
  const [vault, setVault] = useState<CryptoKey | null>(null);
  const [current, setCurrent] = useState(route);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [name, setName] = useState('');
  const [mode, setMode] = useState<'create' | 'login'>('create');
  const [modal, setModal] = useState<'add' | 'recovery' | null>(null);
  const [recoveryDownload, setRecoveryDownload] = useState('');
  const [recoveryInput, setRecoveryInput] = useState('');
  const [label, setLabel] = useState('Demo account');
  const [username, setUsername] = useState('demo@example.test');
  const [password, setPassword] = useState('');
  const [selected, setSelected] = useState('');
  const [message, setMessage] = useState('');
  const [lease, setLease] = useState(86400);
  const [detail, setDetail] = useState<ApprovalDetail | null>(null);
  const messagesEnd = useRef<HTMLDivElement>(null);

  const navigate = useCallback((path: string) => { history.pushState(null, '', path); setCurrent(route()); setError(''); }, []);
  const refresh = useCallback(async () => {
    try { const next = await api<State>('/state'); setState(next); return next; }
    catch (err) { if (err instanceof APIError && err.status === 401) { setState(null); setVault(null); return null; } throw err; }
  }, []);
  useEffect(() => {
    void refresh().catch(err => setError(err.message)).finally(() => setLoading(false));
    const update = () => setCurrent(route()); window.addEventListener('popstate', update);
    return () => window.removeEventListener('popstate', update);
  }, [refresh]);
  useEffect(() => {
    if (!state?.id) return;
    const interval = window.setInterval(() => { if (document.visibilityState === 'visible') void refresh().catch(() => {}); }, 5000);
    return () => clearInterval(interval);
  }, [state?.id, refresh]);
  useEffect(() => {
    if (!selected && state?.items?.length) setSelected(state.items[0].id);
  }, [state?.items, selected]);
  useEffect(() => { messagesEnd.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, [state?.messages?.length]);
  useEffect(() => {
    setDetail(null);
    if (current.page !== 'approval' || !state?.id) return;
    let alive = true;
    void api<ApprovalDetail>(`/approvals/${current.id}`).then(value => { if (alive) setDetail(value); }).catch(err => { if (alive) setError(err.message); });
    return () => { alive = false; };
  }, [current.page, current.id, state?.id, state?.approvals?.find(item => item.id === current.id)?.status]);

  async function run(task: string, fn: () => Promise<void>) {
    if (busy) return;
    setBusy(task); setError(''); setNotice('');
    try { await fn(); }
    catch (err) { setError(err instanceof Error ? err.name === 'NotAllowedError' ? 'Passkey verification was cancelled or timed out. You can try again.' : err.message : 'Something went wrong. Try again.'); }
    finally { setBusy(''); }
  }

  async function finishUnlock(account: State, prf?: ArrayBuffer) {
    if (!prf) throw new Error('This passkey does not support vault encryption (WebAuthn PRF). Try a supported passkey provider. Existing vaults can also be unlocked with their recovery key.');
    const wrapping = await derive(prf);
    new Uint8Array(prf).fill(0);
    if (account.vaultKey) {
      const raw = await open(wrapping, account.vaultKey, vaultAAD(account.id));
      try { setVault(await aes(raw)); } finally { raw.fill(0); }
    } else {
      const raw = random(); const recovery = random();
      try {
        const vmk = await aes(raw);
        const next = await api<State>('/vault/init', { vaultKey: await seal(wrapping, raw, vaultAAD(account.id)), recoveryKey: await seal(await aes(recovery), raw, vaultAAD(account.id)) });
        setState(next); setVault(vmk); setRecoveryDownload(b64(recovery));
        setNotice('');
      } finally { raw.fill(0); recovery.fill(0); }
    }
  }

  async function login(accountName: string) {
    const ceremony = await api<Ceremony>('/auth/login/options', { name: accountName });
    const assertion = await authenticate(ceremony);
    const next = await api<State>('/auth/login/verify', { token: ceremony.token, credential: assertion.credential });
    setState(next);
    await finishUnlock(next, assertion.prf);
  }

  function authSubmit(event: FormEvent) {
    event.preventDefault();
    void run(mode === 'create' ? 'Creating your passkey…' : 'Verifying your passkey…', async () => {
      if (mode === 'create') {
        const ceremony = await api<Ceremony>('/auth/register/options', { name });
        const credential = await createPasskey(ceremony);
        const next = await api<State>('/auth/register/verify', { token: ceremony.token, credential });
        setState(next);
        await login(next.name);
      } else { await login(name); }
    });
  }

  function saveRecovery() {
    const file = `Keyhold vault recovery key\nAccount: ${state?.name}\nOrigin: ${location.origin}\nKey: ${recoveryDownload}\n\nKeep this file private. It unlocks your vault after account sign-in. It does not replace account authentication.\n`;
    const url = URL.createObjectURL(new Blob([file], { type: 'text/plain' }));
    const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'keyhold-recovery.txt'; anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000); setRecoveryDownload('');
  }

  function addCredential(event: FormEvent) {
    event.preventDefault();
    void run('Encrypting credential…', async () => {
      if (!state || !vault) throw new Error('Unlock your vault first.');
      const item = await encryptItem(vault, state.id, label.trim(), username.trim(), password);
      setState(await api<State>('/vault/items', item)); setSelected(item.id); setPassword(''); setModal(null); setNotice('Credential saved.');
    });
  }

  function send(event?: FormEvent) {
    event?.preventDefault();
    void run('Checking credential access…', async () => {
      if (!selected) throw new Error('Add a demo credential to your vault first.');
      setState(await api<State>('/chat/messages', { text: message.trim() || 'Sign in to the demo service and read my profile.', itemId: selected, leaseSeconds: lease }));
      setMessage('');
    });
  }

  async function approve() {
    if (!state || !detail) return;
    const item = state.items?.find(item => item.id === detail.request.itemId);
    if (!item || detail.keyId !== detail.request.keyId) throw new Error('This request is no longer valid. Request access again.');
    const ceremony = await api<Ceremony>(`/approvals/${detail.request.id}/options`, {});
    const assertion = await authenticate(ceremony);
    let key = vault;
    if (assertion.prf && state.vaultKey) {
      const wrapping = await derive(assertion.prf); new Uint8Array(assertion.prf).fill(0);
      const raw = await open(wrapping, state.vaultKey, vaultAAD(state.id));
      try { key = await aes(raw); } finally { raw.fill(0); }
    }
    if (!key) throw new Error('This passkey cannot unlock your vault. Unlock it with your recovery key before approving.');
    const delegatedKey = await delegate(key, state.id, item, detail.publicKey, detail.request.id);
    setState(await api<State>(`/approvals/${detail.request.id}/approve`, { token: ceremony.token, credential: assertion.credential, delegatedKey }));
    setVault(key);
    setState(await api<State>(`/approvals/${detail.request.id}/resume`, {}));
    navigate('/chat'); setNotice('');
  }

  const items = state?.items || [];
  const activeGrants = state?.grants.filter(grant => grant.active && new Date(grant.expiresAt).getTime() > Date.now()) || [];
  const alerts = <>{error && <div className="alert error" role="alert"><X size={18} /><span>{error}</span><button className="icon-button" aria-label="Dismiss error" onClick={() => setError('')}><X size={16} /></button></div>}{notice && <div className="alert success" role="status"><Check size={18} /><span>{notice}</span></div>}</>;

  if (loading) return <div className="loading-screen"><LockKeyhole size={32} /><p>Opening Keyhold…</p></div>;

  if (!state) return <div className="onboarding">
    <header className="landing-header"><a href="/" className="brand"><span className="brand-mark"><LockKeyhole size={21} /></span>keyhold<span className="demo-tag">DEMO</span></a></header>
    <main className="landing-main">
      <section className="signin-card"><div className="card-icon"><Fingerprint size={32} strokeWidth={1.5} /></div><h2>{current.page === 'approval' ? 'Sign in to review access' : mode === 'create' ? 'Create a vault' : 'Sign in'}</h2>
        {alerts}<form onSubmit={authSubmit}><label htmlFor="account-name">Account name</label><input id="account-name" value={name} onChange={event => setName(event.target.value)} placeholder="e.g. alex-demo" minLength={3} maxLength={32} autoComplete="username webauthn" pattern="[a-zA-Z0-9][a-zA-Z0-9_-]{2,31}" required /><button className="primary full" disabled={!!busy}><Fingerprint size={19} />{busy || (mode === 'create' ? 'Create a passkey' : 'Sign in with passkey')}<ArrowRight size={18} /></button></form>
        <button className="text-button full" onClick={() => { setMode(mode === 'create' ? 'login' : 'create'); setError(''); }} disabled={!!busy}>{mode === 'create' ? 'Sign in instead' : 'Create a vault'}</button>
        <div className="signin-foot"><LockKeyhole size={14} /><span>Demo credentials only.<br />Requires a PRF-capable passkey.</span></div>
      </section>
    </main>
  </div>;

  return <div className="app-shell">
    <aside className="sidebar"><a href="/chat" className="brand" onClick={event => { event.preventDefault(); navigate('/chat'); }}><span className="brand-mark"><LockKeyhole size={21} /></span>keyhold<span className="demo-tag">DEMO</span></a>
      <nav aria-label="Main navigation">{([{ page: 'chat', path: '/chat', icon: MessageSquare, text: 'Personal agent' }, { page: 'vault', path: '/vault', icon: KeyRound, text: 'Credential vault' }, { page: 'activity', path: '/activity', icon: Clock3, text: 'Activity' }] as const).map(link => <button key={link.page} className={`nav-item ${current.page === link.page ? 'selected' : ''}`} onClick={() => navigate(link.path)}><link.icon size={19} />{link.text}{link.page === 'vault' && <span className="nav-count">{items.length}</span>}</button>)}</nav>
      <div className="sidebar-bottom"><div className="account-row"><span className="avatar">{state.name.slice(0,1).toUpperCase()}</span><div><strong>{state.name}</strong></div><button className="icon-button" aria-label="Sign out" title="Sign out" onClick={() => void run('Signing out…', async () => { await api('/auth/logout', {}); setState(null); setVault(null); setRecoveryDownload(''); })}><LogOut size={18} /></button></div></div>
    </aside>
    <div className="app-main"><header className="topbar"><h1>{current.page === 'chat' ? 'Personal agent' : current.page === 'vault' ? 'Credential vault' : current.page === 'activity' ? 'Activity' : 'Access approval'}</h1><div className="topbar-right"><span className={`status-chip ${vault ? 'unlocked' : ''}`}><span className="dot" />Vault {vault ? 'unlocked' : 'locked'}</span>{vault ? <button className="quiet-button" onClick={() => { setVault(null); setNotice('Vault locked. Active grants remain available until they expire or are revoked.'); }}><LockKeyhole size={15} />Lock</button> : <button className="quiet-button" disabled={!!busy} onClick={() => void run('Unlocking vault…', () => login(state.name))}><Fingerprint size={16} />Unlock</button>}<button className="icon-button mobile-only" aria-label="Sign out" disabled={!!busy} onClick={() => void run('Signing out…', async () => { await api('/auth/logout', {}); setState(null); setVault(null); setRecoveryDownload(''); })}><LogOut size={16} /></button></div></header>
      <main className="content">{alerts}
        {!state.vaultKey && <div className="setup-banner"><div><strong>Set up vault</strong><p>Verify your passkey to finish setup.</p></div><button className="primary" disabled={!!busy} onClick={() => void run('Setting up vault…', () => login(state.name))}>Finish setup<ArrowRight size={16} /></button></div>}
        {recoveryDownload && <div className="setup-banner recovery-banner"><div><strong>Save your recovery key</strong><p>Keep it private. It unlocks this vault after sign-in.</p></div><button className="secondary" onClick={saveRecovery}><ArrowDownToLine size={16} />Download recovery key</button></div>}

        {current.page === 'chat' && <>
          <div className="agent-layout"><section className="chat-panel" aria-label="Agent conversation"><div className="chat-panel-header"><span className="agent-avatar"><Sparkles size={19} /></span><div><strong>Personal agent</strong><small>Demo service</small></div><span className="online-indicator"><span className="dot" />Ready</span></div>
            <div className="chat-messages">{!state.messages?.length ? <div className="chat-welcome"><span className="welcome-symbol"><Sparkles size={29} strokeWidth={1.4} /></span><button className="suggestion" disabled={!!busy || !items.length} onClick={() => send()}><KeyRound size={17} />Read my demo profile<ArrowUpRight /></button>{!items.length && <button className="text-button" onClick={() => navigate('/vault')}>Add a credential<ArrowRight size={15} /></button>}</div> : state.messages.map(msg => <div className={`message ${msg.role}`} key={msg.id}>{msg.role === 'assistant' && <span className="small-agent"><Sparkles size={15} /></span>}<div className="message-content"><div className="bubble"><p>{msg.text}</p>{msg.approvalId && <a className="approval-link" href={`/approve/${msg.approvalId}`} onClick={event => { event.preventDefault(); navigate(`/approve/${msg.approvalId}`); }}><Fingerprint size={18} />Review access request<ChevronRight size={17} /></a>}</div><small>{msg.role === 'user' ? 'You' : 'Personal agent'} · {time(msg.at)}</small></div></div>)}<div ref={messagesEnd} /></div>
            <form className="composer" onSubmit={send}><div className="composer-options"><label>Credential<select aria-label="Credential to use" value={selected} onChange={event => setSelected(event.target.value)}><option value="" disabled>Select a credential</option>{items.map(item => <option value={item.id} key={item.id}>{item.label}</option>)}</select></label><label>Requested access<select aria-label="Requested access duration" value={lease} onChange={event => setLease(Number(event.target.value))}><option value={86400}>24 hours</option><option value={3600}>1 hour</option><option value={60}>1 minute · test expiry</option></select></label></div><div className="composer-input"><input aria-label="Message your agent" value={message} onChange={event => setMessage(event.target.value)} placeholder="Read my demo profile…" maxLength={2000} /><button className="send-button" aria-label="Send message" disabled={!!busy || !selected}><Send size={18} /></button></div></form>
          </section><aside className="context-panel"><div className="context-heading"><ShieldCheck size={19} /><h2>Active grants</h2></div><div className="context-section">{activeGrants.length ? activeGrants.map(grant => <div className="mini-grant" key={grant.id}><div className="mini-grant-title"><span className="dot" /><strong>{grant.label}</strong></div><p>{remaining(grant.expiresAt)} · {grant.uses} use{grant.uses === 1 ? '' : 's'}</p><button className="text-button danger" disabled={!!busy} onClick={() => void run('Revoking access…', async () => { setState(await api<State>(`/grants/${grant.id}/revoke`, {})); setNotice('Access revoked.'); })}>Revoke access</button></div>) : <div className="empty-grants"><LockKeyhole size={24} strokeWidth={1.4} /><p>No access granted</p></div>}</div></aside></div>
        </>}

        {current.page === 'vault' && <>
          <div className="vault-toolbar"><button className="primary" disabled={!!busy || !vault} onClick={() => setModal('add')}><Plus size={18} />Add credential</button></div>
          {!vault && <div className="locked-banner"><LockKeyhole size={20} /><span>Unlock your vault to add credentials.</span><button className="text-button" onClick={() => setModal('recovery')}>Use a recovery key</button></div>}
          <section className="credential-list">{items.length ? items.map(item => <article className="credential-row" key={item.id}><span className="credential-icon"><KeyRound size={23} strokeWidth={1.5} /></span><div><h2>{item.label}</h2></div><button className="quiet-button" disabled={!!busy} onClick={() => { setSelected(item.id); navigate('/chat'); }}>Use with agent<ArrowRight size={16} /></button></article>) : <div className="vault-empty"><span className="welcome-symbol"><KeyRound size={30} strokeWidth={1.4} /></span><h2>No credentials</h2><button className="primary" disabled={!vault} onClick={() => setModal('add')}><Plus size={18} />Add your first credential</button></div>}</section>

          <section className="grant-section"><div className="section-title"><h2>Access history</h2><span>{state.grants.length} grant{state.grants.length === 1 ? '' : 's'}</span></div>{state.grants.length ? [...state.grants].reverse().map(grant => <div className="grant-row" key={grant.id}><Clock3 size={18} /><div><strong>{grant.label}</strong><small>Read demo profile · {grant.uses} uses</small></div><span className={`pill ${grant.revokedAt ? 'neutral' : remaining(grant.expiresAt) === 'Expired' ? 'neutral' : 'green'}`}>{grant.revokedAt ? 'Revoked' : remaining(grant.expiresAt)}</span>{grant.active && <button className="text-button danger" disabled={!!busy} onClick={() => void run('Revoking access…', async () => setState(await api<State>(`/grants/${grant.id}/revoke`, {})))}>Revoke</button>}</div>) : <p className="muted">No grants</p>}</section>
        </>}

        {current.page === 'activity' && <><section className="activity-list">{state.events?.length ? [...state.events].reverse().map(event => <article key={event.id} className="activity-row"><span className="activity-dot"><ShieldCheck size={18} /></span><div><h2>{event.kind.replace(/_/g, ' ')}</h2><p>{event.detail}</p></div><time dateTime={event.at}>{new Date(event.at).toLocaleDateString([], { month: 'short', day: 'numeric' })} · {time(event.at)}</time></article>) : <div className="vault-empty"><Clock3 size={30} /><h2>No activity yet.</h2></div>}</section></>}

        {current.page === 'approval' && <><button className="text-button back-link" onClick={() => navigate('/chat')}><ArrowLeft size={16} />Back to your agent</button>{detail ? <section className="approval-card"><div className="approval-symbol"><Fingerprint size={38} strokeWidth={1.4} /></div><h2>Approve credential access</h2><dl className="approval-details"><div><dt>Requested by</dt><dd><Sparkles size={17} />Personal agent</dd></div><div><dt>Credential</dt><dd><KeyRound size={17} />{detail.request.label}</dd></div><div><dt>Allowed action</dt><dd>Read demo profile</dd></div><div><dt>Destination</dt><dd>Local demo service</dd></div><div><dt>Access duration</dt><dd><Clock3 size={17} />{duration(detail.request.leaseSeconds)}</dd></div></dl>{detail.request.status === 'pending' && new Date(detail.request.expiresAt).getTime() > Date.now() ? <><div className="approval-actions"><button className="secondary" disabled={!!busy} onClick={() => void run('Denying request…', async () => { setState(await api<State>(`/approvals/${detail.request.id}/deny`, {})); navigate('/chat'); setNotice('Request denied.'); })}>Deny request</button><button className="primary" disabled={!!busy} onClick={() => void run('Verifying approval…', approve)}><Fingerprint size={19} />{busy || 'Approve with passkey'}</button></div><p className="approval-foot"><ShieldCheck size={15} />Request expires at {time(detail.request.expiresAt)}.</p></> : <div className="approval-result"><span className="pill green">{detail.request.status === 'pending' ? 'Expired' : detail.request.status}</span>{detail.request.status === 'approved' && <button className="primary" disabled={!!busy} onClick={() => void run('Resuming action…', async () => { setState(await api<State>(`/approvals/${detail.request.id}/resume`, {})); navigate('/chat'); })}>Resume action<ArrowRight size={16} /></button>}<p>{detail.request.status === 'completed' ? 'Completed. View the result in chat.' : 'Request closed.'}</p></div>}</section> : !error && <p className="muted">Loading access request…</p>}</>}
      </main><footer className="app-footer">Demo credentials only.</footer>
    </div>
    {modal === 'add' && <Modal title="Add a credential" close={() => { setModal(null); setPassword(''); }}><p className="modal-description">Use a fake login.</p>{error && <p className="alert error" role="alert">{error}</p>}<form onSubmit={addCredential}><label htmlFor="credential-label">Credential name</label><input id="credential-label" value={label} onChange={e => setLabel(e.target.value)} maxLength={80} required /><label htmlFor="credential-username">Username</label><input id="credential-username" value={username} onChange={e => setUsername(e.target.value)} maxLength={200} autoComplete="off" required /><label htmlFor="credential-password">Password</label><input id="credential-password" type="password" value={password} onChange={e => setPassword(e.target.value)} maxLength={1000} autoComplete="new-password" placeholder="A fake demo password" required /><button className="primary full" disabled={!!busy}><LockKeyhole size={18} />{busy || 'Encrypt and save'}</button></form></Modal>}
    {modal === 'recovery' && <Modal title="Unlock with recovery key" close={() => { setModal(null); setRecoveryInput(''); }}><p className="modal-description">Paste the key from your recovery file.</p>{error && <p className="alert error" role="alert">{error}</p>}<form onSubmit={event => { event.preventDefault(); void run('Unlocking with recovery key…', async () => { if (!state.recoveryKey) throw new Error('No recovery wrapper exists for this vault.'); const key = unb64(recoveryInput.trim()); if (key.length !== 32) throw new Error('Recovery key must be 32 bytes.'); try { const raw = await open(await aes(key), state.recoveryKey, vaultAAD(state.id)); try { setVault(await aes(raw)); } finally { raw.fill(0); } } finally { key.fill(0); } setRecoveryInput(''); setModal(null); setNotice('Vault unlocked with recovery key.'); }); }}><label htmlFor="recovery-key">Recovery key</label><input id="recovery-key" type="password" value={recoveryInput} onChange={e => setRecoveryInput(e.target.value)} autoComplete="off" required /><button className="primary full" disabled={!!busy}><KeyRound size={18} />Unlock vault</button></form></Modal>}
    {busy && <div className="busy-indicator" role="status"><span className="spinner" />{busy}</div>}
  </div>;
}

function ArrowUpRight() { return <ArrowRight size={17} className="arrow-diagonal" />; }

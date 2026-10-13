import React, { useEffect, useState } from 'react';

export function LoginForm({ unlock }: { unlock: () => Promise<void> }) {
  const [passwordMode, setPasswordMode] = useState(false), [available, setAvailable] = useState(false), [ready, setReady] = useState(false);
  const [password, setPassword] = useState(''), [code, setCode] = useState(''), [token, setToken] = useState('');
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  useEffect(() => { fetch('/api/v1/auth/status').then(response => response.json()).then(value => { setAvailable(!!value.password_totp); setPasswordMode(!!value.password_totp); }).catch(() => setError('Could not load login settings.')).finally(() => setReady(true)); }, []);
  async function submit(event: React.FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      if (passwordMode) {
        const response = await fetch('/api/v1/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password, code }) });
        if (!response.ok) { const value = await response.json(); throw new Error(typeof value.detail === 'string' ? value.detail : 'Check your password and six-digit verification code.'); }
        sessionStorage.removeItem('psc-token'); setPassword(''); setCode('');
      } else sessionStorage.setItem('psc-token', token);
      await unlock();
    } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  return <form onSubmit={submit}><div className="modal-body">{passwordMode ? <><label className="field">Owner password<input autoFocus type="password" autoComplete="current-password" maxLength={1024} required value={password} onChange={e => setPassword(e.target.value)} /></label><label className="field">Verification code<input inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required value={code} onChange={e => setCode(e.target.value)} /></label><p className="muted">Use the current six-digit code from your authenticator. Sessions expire after 12 hours.</p></> : <><label className="field">Controller token<input autoFocus type="password" autoComplete="off" required value={token} onChange={e => setToken(e.target.value)} /></label><p className="muted">Kept in this browser tab’s session storage.</p></>}{available && <button type="button" className="text-button" onClick={() => { setPasswordMode(!passwordMode); setError(''); }}>{passwordMode ? 'Use a controller token' : 'Use password and authenticator'}</button>}{error && <p role="alert" className="warning-text">{error}</p>}</div><div className="modal-actions"><button className="button primary" type="submit" disabled={busy || !ready}>{busy ? 'Checking…' : 'Unlock workspace'}</button></div></form>;
}

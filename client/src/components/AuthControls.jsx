import { useEffect, useState } from 'react'
import { supabase, isSupabaseConfigured } from '../lib/supabase.js'
import { subscribeToAuthState } from '../lib/authState.js'

function authErrorMessage(error, action) {
  switch (error?.code) {
    case 'invalid_credentials':
      return 'Email or password is incorrect.'
    case 'email_not_confirmed':
      return 'Confirm your email address before signing in.'
    case 'user_already_exists':
      return 'An account already exists for this email. Try signing in.'
    default:
      return `Could not ${action}. Check your connection and Supabase Auth settings, then try again.`
  }
}

export default function AuthControls() {
  const [session, setSession] = useState(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mode, setMode] = useState('signin')
  const [isOpen, setIsOpen] = useState(false)
  const [isBusy, setIsBusy] = useState(false)
  const [errorMessage, setErrorMessage] = useState('')
  const [notice, setNotice] = useState('')

  useEffect(() => {
    if (!isSupabaseConfigured) return undefined
    return subscribeToAuthState(supabase.auth, setSession)
  }, [])

  async function handleSubmit(event) {
    event.preventDefault()
    setErrorMessage('')
    setNotice('')

    const normalizedEmail = email.trim()
    if (!normalizedEmail || !password) {
      setErrorMessage('Enter your email and password.')
      return
    }

    setIsBusy(true)
    try {
      if (mode === 'signup') {
        const { data, error } = await supabase.auth.signUp({
          email: normalizedEmail,
          password,
        })
        if (error) throw error

        if (data.session) {
          setSession(data.session)
          setNotice('Your account is ready.')
        } else {
          setNotice('Check your email for a confirmation link to finish creating your account.')
        }
        setPassword('')
      } else {
        const { data, error } = await supabase.auth.signInWithPassword({
          email: normalizedEmail,
          password,
        })
        if (error) throw error
        setSession(data.session)
        setPassword('')
        setNotice('You are signed in.')
      }
    } catch (error) {
      setErrorMessage(authErrorMessage(error, mode === 'signup' ? 'create your account' : 'sign in'))
    } finally {
      setIsBusy(false)
    }
  }

  async function handleSignOut() {
    setErrorMessage('')
    setNotice('')
    setIsBusy(true)
    try {
      const { error } = await supabase.auth.signOut()
      if (error) throw error
      setSession(null)
      setNotice('You are signed out.')
    } catch {
      setErrorMessage('Could not sign out. Check your connection and try again.')
    } finally {
      setIsBusy(false)
    }
  }

  if (!isSupabaseConfigured) {
    if (!import.meta.env.DEV) return null
    return <span className="auth-unavailable" title="Configure the Supabase Vite environment variables">Auth unavailable</span>
  }

  return (
    <div className="auth-control">
      <button
        type="button"
        className="auth-toggle"
        aria-expanded={isOpen}
        aria-controls="auth-panel"
        onClick={() => {
          setIsOpen((open) => !open)
          setErrorMessage('')
          setNotice('')
        }}
      >
        {session ? 'Account' : 'Sign in'}
      </button>

      {isOpen && (
        <section className="auth-panel" id="auth-panel" aria-label="Account">
          {session ? (
            <>
              <p className="auth-status">Signed in as <strong>{session.user?.email || 'your account'}</strong></p>
              <button type="button" className="auth-submit" onClick={handleSignOut} disabled={isBusy}>
                {isBusy ? 'Signing out…' : 'Sign out'}
              </button>
            </>
          ) : (
            <>
              <h2>{mode === 'signup' ? 'Create account' : 'Sign in to Lakewest AI'}</h2>
              <form onSubmit={handleSubmit}>
                <label htmlFor="auth-email">Email</label>
                <input
                  id="auth-email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  disabled={isBusy}
                />
                <label htmlFor="auth-password">Password</label>
                <input
                  id="auth-password"
                  type="password"
                  autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={isBusy}
                />
                <button type="submit" className="auth-submit" disabled={isBusy}>
                  {isBusy ? 'Please wait…' : mode === 'signup' ? 'Create account' : 'Sign in'}
                </button>
              </form>
              <button
                type="button"
                className="auth-mode-toggle"
                onClick={() => {
                  setMode((current) => current === 'signup' ? 'signin' : 'signup')
                  setErrorMessage('')
                  setNotice('')
                }}
                disabled={isBusy}
              >
                {mode === 'signup' ? 'Already have an account? Sign in' : 'Create an account'}
              </button>
            </>
          )}
          {errorMessage && <p className="auth-message auth-error" role="alert">{errorMessage}</p>}
          {notice && <p className="auth-message" role="status">{notice}</p>}
          <p className="auth-chat-note">Chat remains available while signed out.</p>
        </section>
      )}
    </div>
  )
}

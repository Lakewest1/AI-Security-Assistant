const test = require('node:test')
const assert = require('node:assert/strict')

test('auth state restores the session and unsubscribes on cleanup', async () => {
  const { subscribeToAuthState } = await import('../client/src/lib/authState.js')
  const restoredSession = { user: { email: 'user@example.test' } }
  const states = []
  let unsubscribed = false
  const auth = {
    onAuthStateChange() {
      return { data: { subscription: { unsubscribe: () => { unsubscribed = true } } } }
    },
    async getSession() {
      return { data: { session: restoredSession }, error: null }
    },
  }

  const cleanup = subscribeToAuthState(auth, (session) => states.push(session))
  await new Promise((resolve) => setImmediate(resolve))

  assert.deepEqual(states, [restoredSession])
  cleanup()
  assert.equal(unsubscribed, true)
})

test('auth events take precedence over a late session restore and stop after cleanup', async () => {
  const { subscribeToAuthState } = await import('../client/src/lib/authState.js')
  const states = []
  let listener
  let resolveSession
  let unsubscribed = false
  const auth = {
    onAuthStateChange(callback) {
      listener = callback
      return { data: { subscription: { unsubscribe: () => { unsubscribed = true } } } }
    },
    getSession() {
      return new Promise((resolve) => { resolveSession = resolve })
    },
  }

  const cleanup = subscribeToAuthState(auth, (session) => states.push(session))
  await new Promise((resolve) => setImmediate(resolve))
  const signedInSession = { user: { email: 'next@example.test' } }
  listener('SIGNED_IN', signedInSession)
  resolveSession({ data: { session: null }, error: null })
  await new Promise((resolve) => setImmediate(resolve))

  assert.deepEqual(states, [signedInSession])
  cleanup()
  listener('SIGNED_OUT', null)
  assert.deepEqual(states, [signedInSession])
  assert.equal(unsubscribed, true)
})

test('failed session restoration resolves to a signed-out state', async () => {
  const { subscribeToAuthState } = await import('../client/src/lib/authState.js')
  const states = []
  const auth = {
    onAuthStateChange() {
      return { data: { subscription: { unsubscribe() {} } } }
    },
    async getSession() {
      throw new Error('private token-like provider detail')
    },
  }

  const cleanup = subscribeToAuthState(auth, (session) => states.push(session))
  await new Promise((resolve) => setImmediate(resolve))

  assert.deepEqual(states, [null])
  cleanup()
})

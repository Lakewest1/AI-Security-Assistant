const test = require('node:test')
const assert = require('node:assert/strict')

test('agent requests attach the current Supabase access token only in Authorization', async () => {
  const { fetchAgentRequest } = await import('../client/src/lib/agentRequest.js')
  let captured
  const auth = { async getSession() { return { data: { session: { access_token: 'fixture-token' } }, error: null } } }
  const response = await fetchAgentRequest('https://api.example.test/api/agent', { method: 'POST', body: '{}' }, auth, async (url, options) => {
    captured = { url, options }
    return new Response('{}', { status: 200 })
  })

  assert.equal(response.status, 200)
  assert.equal(captured.options.headers.get('Authorization'), 'Bearer fixture-token')
  assert.equal(captured.url, 'https://api.example.test/api/agent')
  assert.equal(captured.options.headers.has('access_token'), false)
  assert.equal(captured.url.includes('fixture-token'), false)
})

test('agent request refreshes once after 401 and retries with the refreshed session token', async () => {
  const { fetchAgentRequest } = await import('../client/src/lib/agentRequest.js')
  let refreshCalls = 0
  const sentTokens = []
  const auth = {
    async getSession() { return { data: { session: { access_token: 'expired-token' } }, error: null } },
    async refreshSession() {
      refreshCalls += 1
      return { data: { session: { access_token: 'refreshed-token' } }, error: null }
    },
  }
  const response = await fetchAgentRequest('/api/agent', { method: 'POST' }, auth, async (_url, options) => {
    sentTokens.push(options.headers.get('Authorization'))
    return new Response('{}', { status: sentTokens.length === 1 ? 401 : 200 })
  })

  assert.equal(response.status, 200)
  assert.equal(refreshCalls, 1)
  assert.deepEqual(sentTokens, ['Bearer expired-token', 'Bearer refreshed-token'])
})

test('unauthenticated agent request remains token-free and preserves backend 401', async () => {
  const { fetchAgentRequest } = await import('../client/src/lib/agentRequest.js')
  let authorization
  const auth = { async getSession() { return { data: { session: null }, error: null } } }
  const response = await fetchAgentRequest('/api/agent', { method: 'POST' }, auth, async (_url, options) => {
    authorization = options.headers.get('Authorization')
    return new Response('{"error":"Authentication required."}', { status: 401 })
  })
  assert.equal(response.status, 401)
  assert.equal(authorization, null)
})

test('session lookup and refresh failures do not expose credentials or hide backend response', async () => {
  const { fetchAgentRequest } = await import('../client/src/lib/agentRequest.js')
  const responses = []
  const auth = {
    async getSession() { return { data: { session: { access_token: 'fixture-secret' } }, error: null } },
    async refreshSession() { throw new Error('refresh failure fixture-secret') },
  }
  const response = await fetchAgentRequest('/api/agent', { method: 'POST' }, auth, async (_url, options) => {
    responses.push(options)
    return new Response('{"error":"The access token is invalid or expired."}', { status: 401 })
  })
  assert.equal(response.status, 401)
  assert.equal(responses.length, 1)
})

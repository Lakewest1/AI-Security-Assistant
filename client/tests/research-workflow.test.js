import assert from 'node:assert/strict'
import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { test } from 'node:test'
import { createServer } from 'vite'
import { fileURLToPath } from 'node:url'
import {
  createResearchWorkflowApi,
  createResearchWorkflowController,
} from '../src/lib/researchWorkflow.js'

const API_URL = 'http://127.0.0.1:5000'

function preview(query = 'Exact server preview query', overrides = {}) {
  return {
    schemaVersion: 1,
    mode: 'research',
    status: 'confirmation_required',
    result: {
      query,
      provider: 'Tavily',
      maxResults: 3,
      confirmationId: 'synthetic-confirmation-id',
      expiresAt: '2030-01-01T00:05:00.000Z',
      ...overrides,
    },
    sources: [],
    limitations: ['No provider request has been made.'],
    metadata: { executionStatus: 'not_started' },
  }
}

test('frontend API client uses authenticated POST requests and the backend prepare/confirm schemas', async () => {
  const requests = []
  const auth = { getSession: async () => ({ data: { session: { access_token: 'synthetic-access-token' } } }) }
  const api = createResearchWorkflowApi({
    apiUrl: API_URL,
    auth,
    fetchImpl: async (url, options) => {
      requests.push({ url, options })
      return Response.json(requests.length === 1 ? preview('Server-returned wording') : {
        schemaVersion: 1, mode: 'research', status: 'unavailable', result: null,
        sources: [], limitations: [], metadata: { executionStatus: 'not_started' },
        error: { code: 'RESEARCH_PROVIDER_DISABLED', message: 'fixed backend text' },
      }, { status: requests.length === 1 ? 201 : 503 })
    },
  })

  const prepared = await api.prepare({ query: 'Original user wording', maxResults: 4 })
  assert.equal(prepared.result.query, 'Server-returned wording')
  await assert.rejects(api.confirm({
    confirmationId: prepared.result.confirmationId,
    query: prepared.result.query,
    provider: prepared.result.provider,
  }), (error) => error.code === 'RESEARCH_PROVIDER_DISABLED')

  assert.equal(requests[0].url, `${API_URL}/api/workflows/research/prepare`)
  assert.equal(requests[1].url, `${API_URL}/api/workflows/research/confirm`)
  for (const request of requests) {
    assert.equal(request.options.method, 'POST')
    assert.equal(request.options.headers.get('content-type'), 'application/json')
    assert.equal(request.options.headers.get('authorization'), 'Bearer synthetic-access-token')
    assert.equal(request.options.credentials, 'omit')
    assert.equal(request.options.redirect, 'error')
  }
  assert.deepEqual(JSON.parse(requests[0].options.body), {
    query: 'Original user wording', options: { maxResults: 4 },
  })
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    confirmationId: 'synthetic-confirmation-id',
    query: 'Server-returned wording',
    provider: 'Tavily',
    confirmed: true,
  })
})

test('preview state retains the exact server query/provider/count/expiry and waits for explicit confirm', async () => {
  let confirmCalls = 0
  const flow = createResearchWorkflowController({
    api: {
      prepare: async () => preview('Exact server-returned query', {
        maxResults: 5,
        expiresAt: '2030-02-03T04:05:06.000Z',
      }),
      confirm: async () => {
        confirmCalls += 1
        return { status: 'unavailable', error: { code: 'RESEARCH_PROVIDER_DISABLED' } }
      },
    },
    now: () => Date.parse('2030-02-03T04:00:00.000Z'),
  })
  flow.setQuery('Question sent to prepare')
  await flow.prepare()
  const state = flow.getState()
  assert.equal(state.preview.query, 'Exact server-returned query')
  assert.equal(state.preview.provider, 'Tavily')
  assert.equal(state.preview.maxResults, 5)
  assert.equal(state.preview.expiresAt, '2030-02-03T04:05:06.000Z')
  assert.equal(confirmCalls, 0)

  await flow.confirm()
  assert.equal(confirmCalls, 1)
})

test('Research panel renders the exact backend preview and does not display its authorization ID', async () => {
  const workflowController = createResearchWorkflowController({
    api: {
      prepare: async () => preview('Server exact query & wording', {
        provider: 'Tavily',
        maxResults: 4,
        confirmationId: 'synthetic-render-only-confirmation-id',
        expiresAt: '2030-04-05T06:07:08.000Z',
      }),
      confirm: async () => ({ status: 'unavailable', error: { code: 'RESEARCH_PROVIDER_DISABLED' } }),
    },
    now: () => Date.parse('2030-04-05T06:00:00.000Z'),
  })
  workflowController.setQuery('Different original input')
  await workflowController.prepare()

  const vite = await createServer({
    root: fileURLToPath(new URL('../', import.meta.url)),
    configFile: false,
    appType: 'custom',
    server: { middlewareMode: true },
  })
  try {
    const { default: ResearchPanel } = await vite.ssrLoadModule('/src/components/ResearchPanel.jsx')
    const markup = renderToStaticMarkup(React.createElement(ResearchPanel, {
      apiUrl: API_URL,
      workflowController,
      onClose: () => {},
    }))
    assert.match(markup, /Server exact query &amp; wording/)
    assert.match(markup, /Tavily/)
    assert.match(markup, /Maximum results/)
    assert.match(markup, />4</)
    assert.match(markup, /2030-04-05T06:07:08\.000Z/)
    assert.match(markup, /Confirm query/)
    assert.match(markup, /Cancel preview/)
    assert.equal(markup.includes('synthetic-render-only-confirmation-id'), false)
  } finally {
    await vite.close()
  }
})

test('cancel clears the preview and never submits confirmation', async () => {
  let confirmCalls = 0
  const flow = createResearchWorkflowController({
    api: {
      prepare: async () => preview(),
      confirm: async () => { confirmCalls += 1; return { status: 'success', sources: [] } },
    },
  })
  flow.setQuery('Public question')
  await flow.prepare()
  assert.ok(flow.getState().preview)
  flow.cancel()
  assert.equal(flow.getState().preview, null)
  assert.equal(flow.getState().phase, 'idle')
  assert.equal(confirmCalls, 0)
})

test('editing the query invalidates the old preview and requires a new prepare', async () => {
  const preparedQueries = []
  const confirmed = []
  let id = 0
  const flow = createResearchWorkflowController({
    api: {
      prepare: async ({ query }) => {
        preparedQueries.push(query)
        id += 1
        return preview(query.trim(), { confirmationId: `synthetic-confirmation-${id}` })
      },
      confirm: async (data) => { confirmed.push(data); return { status: 'unavailable', error: { code: 'RESEARCH_PROVIDER_DISABLED' } } },
    },
  })
  flow.setQuery('First public question')
  await flow.prepare()
  flow.setQuery('Edited public question')
  assert.equal(flow.getState().preview, null)
  assert.match(flow.getState().error, /Prepare a new preview/)
  await flow.confirm()
  assert.equal(confirmed.length, 0)

  await flow.prepare()
  await flow.confirm()
  assert.deepEqual(preparedQueries, ['First public question', 'Edited public question'])
  assert.equal(confirmed.length, 1)
  assert.equal(confirmed[0].query, 'Edited public question')
  assert.equal(confirmed[0].confirmationId, 'synthetic-confirmation-2')
})

test('expired preview is rejected locally and does not call confirm', async () => {
  let currentTime = Date.parse('2030-01-01T00:00:00.000Z')
  let confirmCalls = 0
  const flow = createResearchWorkflowController({
    api: {
      prepare: async () => preview('Short-lived query', { expiresAt: '2030-01-01T00:00:01.000Z' }),
      confirm: async () => { confirmCalls += 1; return { status: 'success' } },
    },
    now: () => currentTime,
  })
  flow.setQuery('Short-lived query')
  await flow.prepare()
  assert.equal(flow.getState().phase, 'preview')
  currentTime = Date.parse('2030-01-01T00:00:01.000Z')
  await flow.confirm()
  assert.equal(flow.getState().phase, 'expired')
  assert.equal(confirmCalls, 0)
})

test('invalid confirmation and authentication failures use safe, actionable messages', async () => {
  const invalid = createResearchWorkflowController({
    api: {
      prepare: async () => preview(),
      confirm: async () => { throw Object.assign(new Error('provider detail must not surface'), { code: 'RESEARCH_CONFIRMATION_INVALID' }) },
    },
  })
  invalid.setQuery('Public question')
  await invalid.prepare()
  await invalid.confirm()
  assert.equal(invalid.getState().phase, 'expired')
  assert.match(invalid.getState().error, /expired or is invalid/)
  assert.equal(invalid.getState().error.includes('provider detail'), false)

  const authFailure = createResearchWorkflowController({
    api: { prepare: async () => { throw Object.assign(new Error('token must not surface'), { code: 'invalid_token' }) }, confirm: async () => ({}) },
  })
  authFailure.setQuery('Public question')
  await authFailure.prepare()
  assert.match(authFailure.getState().error, /session has expired/)
  assert.equal(authFailure.getState().error.includes('token must not surface'), false)
})

test('missing authentication is returned as a safe sign-in message without forwarding session data', async () => {
  let capturedAuthorization = null
  const api = createResearchWorkflowApi({
    apiUrl: API_URL,
    auth: { getSession: async () => ({ data: { session: null }, error: null }) },
    fetchImpl: async (_url, options) => {
      capturedAuthorization = options.headers.get('authorization')
      return Response.json({ code: 'missing_token', error: 'Authentication required.' }, { status: 401 })
    },
  })
  const flow = createResearchWorkflowController({ api })
  flow.setQuery('Public question')
  await flow.prepare()
  assert.equal(capturedAuthorization, null)
  assert.match(flow.getState().error, /Sign in before using Research/)
  assert.equal(flow.getState().preview, null)
})

test('provider-disabled response is never presented as successful research', async () => {
  const flow = createResearchWorkflowController({
    api: {
      prepare: async () => preview(),
      confirm: async () => {
        throw Object.assign(new Error('provider disabled'), { code: 'RESEARCH_PROVIDER_DISABLED', status: 503 })
      },
    },
  })
  flow.setQuery('Public question')
  await flow.prepare()
  await flow.confirm()
  assert.equal(flow.getState().phase, 'disabled')
  assert.equal(flow.getState().result, null)
  assert.match(flow.getState().error, /currently disabled/)
  assert.equal(flow.getState().preview, null)
})

test('network failures do not expose exception details', async () => {
  const api = createResearchWorkflowApi({ apiUrl: API_URL, fetchImpl: async () => { throw new Error('https://secret.invalid/token=synthetic'); } })
  await assert.rejects(api.prepare({ query: 'Public query' }), (error) => {
    assert.equal(error.code, 'NETWORK_ERROR')
    assert.equal(error.message.includes('secret.invalid'), false)
    return true
  })
})

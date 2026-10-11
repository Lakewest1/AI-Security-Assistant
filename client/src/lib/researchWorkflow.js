import { fetchAgentRequest } from './agentRequest.js'

const SAFE_ERROR_MESSAGES = {
  AUTHENTICATION_REQUIRED: 'Sign in again to use Research. Your query was not submitted for external research.',
  invalid_token: 'Your session has expired. Sign in again before preparing or confirming a query.',
  missing_token: 'Sign in before using Research.',
  RESEARCH_PRIVACY_REJECTED: 'This query may contain personal, confidential, or investigation data and was not prepared.',
  RESEARCH_CONFIRMATION_INVALID: 'This preview expired or is invalid. Prepare a new preview before confirming.',
  RESEARCH_CONFIRMATION_REQUIRED: 'Prepare and review a new query before confirming.',
  RESEARCH_PROVIDER_DISABLED: 'External Research is currently disabled. The backend did not send this query to Tavily.',
  RESEARCH_PROVIDER_UNAVAILABLE: 'The Research provider is unavailable. No successful research result was returned.',
  RESEARCH_CONFIRMATION_UNAVAILABLE: 'A preview could not be created. Try again later.',
  NETWORK_ERROR: 'The Research request could not be completed. Its status is unknown; prepare a new preview before trying again.',
  INVALID_RESPONSE: 'The Research service returned an unexpected response. Prepare the query again.',
}

export class ResearchWorkflowError extends Error {
  constructor(code, status = 0) {
    super(code || 'NETWORK_ERROR')
    this.name = 'ResearchWorkflowError'
    this.code = code || 'NETWORK_ERROR'
    this.status = status
  }
}

export function researchErrorMessage(code) {
  return SAFE_ERROR_MESSAGES[code] || 'Research could not be completed. Review the query and try again.'
}

export function createResearchWorkflowApi({ apiUrl, auth, fetchImpl = fetch }) {
  const baseUrl = String(apiUrl || '').replace(/\/$/, '')

  async function post(action, body) {
    let response
    try {
      response = await fetchAgentRequest(`${baseUrl}/api/workflows/research/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'omit',
        redirect: 'error',
      }, auth, fetchImpl)
    } catch {
      throw new ResearchWorkflowError('NETWORK_ERROR')
    }

    let data
    try {
      data = await response.json()
    } catch {
      data = null
    }
    if (!data || typeof data !== 'object') {
      throw new ResearchWorkflowError(response.status === 401 ? 'AUTHENTICATION_REQUIRED' : 'INVALID_RESPONSE', response.status)
    }
    if (!response.ok) {
      throw new ResearchWorkflowError(data.error?.code || data.code || (response.status === 401 ? 'AUTHENTICATION_REQUIRED' : 'INVALID_RESPONSE'), response.status)
    }
    return data
  }

  return {
    prepare({ query, maxResults = 3 }) {
      return post('prepare', { query, options: { maxResults } })
    },
    confirm({ confirmationId, query, provider }) {
      return post('confirm', { confirmationId, query, provider, confirmed: true })
    },
  }
}

export function createResearchWorkflowController({ api, now = Date.now } = {}) {
  if (!api || typeof api.prepare !== 'function' || typeof api.confirm !== 'function') {
    throw new TypeError('Research workflow API is required')
  }

  let state = {
    query: '',
    maxResults: 3,
    phase: 'idle',
    preview: null,
    previewInput: null,
    result: null,
    error: null,
  }
  const listeners = new Set()

  function snapshot() {
    return { ...state, preview: state.preview ? { ...state.preview } : null }
  }

  function update(patch) {
    state = { ...state, ...patch }
    const current = snapshot()
    for (const listener of listeners) listener(current)
    return current
  }

  function fail(error) {
    const code = error?.code || 'NETWORK_ERROR'
    if (code === 'RESEARCH_PROVIDER_DISABLED') {
      return update({ phase: 'disabled', preview: null, previewInput: null, result: null, error: researchErrorMessage(code) })
    }
    const phase = code === 'RESEARCH_CONFIRMATION_INVALID' ? 'expired' : 'error'
    return update({ phase, preview: null, previewInput: null, result: null, error: researchErrorMessage(code) })
  }

  return {
    getState: snapshot,
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    setQuery(query) {
      const editedPreview = state.preview && query !== state.previewInput
      return update({
        query,
        ...(editedPreview ? {
          phase: 'idle',
          preview: null,
          previewInput: null,
          result: null,
          error: 'The question changed. Prepare a new preview before confirming.',
        } : {}),
      })
    },
    setMaxResults(maxResults) {
      if (state.preview && maxResults !== state.maxResults) {
        return update({
          maxResults,
          phase: 'idle',
          preview: null,
          previewInput: null,
          result: null,
          error: 'The result count changed. Prepare a new preview before confirming.',
        })
      }
      return update({ maxResults })
    },
    cancel() {
      return update({ phase: 'idle', preview: null, previewInput: null, result: null, error: null })
    },
    expire() {
      if (state.preview && Date.parse(state.preview.expiresAt) <= now()) {
        return fail(new ResearchWorkflowError('RESEARCH_CONFIRMATION_INVALID'))
      }
      return snapshot()
    },
    expire() {
      if (state.preview && Date.parse(state.preview.expiresAt) <= now()) {
        return fail(new ResearchWorkflowError('RESEARCH_CONFIRMATION_INVALID'))
      }
      return snapshot()
    },
    async prepare() {
      if (state.phase === 'preparing' || state.phase === 'confirming') return snapshot()
      if (!state.query.trim()) {
        return update({ phase: 'error', preview: null, previewInput: null, error: 'Enter a public-information question to prepare a preview.' })
      }
      const submittedInput = state.query
      const maxResults = state.maxResults
      update({ phase: 'preparing', preview: null, previewInput: null, result: null, error: null })
      try {
        const response = await api.prepare({ query: submittedInput, maxResults })
        const preview = response?.result
        if (response?.status !== 'confirmation_required'
          || typeof preview?.query !== 'string'
          || typeof preview?.provider !== 'string'
          || !Number.isInteger(preview?.maxResults)
          || typeof preview?.confirmationId !== 'string'
          || typeof preview?.expiresAt !== 'string'
          || !Number.isFinite(Date.parse(preview.expiresAt))) {
          throw new ResearchWorkflowError(response?.error?.code || 'INVALID_RESPONSE')
        }
        if (Date.parse(preview.expiresAt) <= now()) throw new ResearchWorkflowError('RESEARCH_CONFIRMATION_INVALID')
        return update({ phase: 'preview', preview, previewInput: submittedInput, error: null })
      } catch (error) {
        return fail(error)
      }
    },
    async confirm() {
      if (state.phase === 'confirming' || !state.preview) return snapshot()
      if (state.query !== state.previewInput) {
        return fail(new ResearchWorkflowError('RESEARCH_CONFIRMATION_INVALID'))
      }
      if (Date.parse(state.preview.expiresAt) <= now()) {
        return fail(new ResearchWorkflowError('RESEARCH_CONFIRMATION_INVALID'))
      }
      const preview = { ...state.preview }
      update({ phase: 'confirming', error: null, result: null })
      try {
        const response = await api.confirm({
          confirmationId: preview.confirmationId,
          query: preview.query,
          provider: preview.provider,
        })
        if (response?.error?.code === 'RESEARCH_PROVIDER_DISABLED') {
          return fail(new ResearchWorkflowError('RESEARCH_PROVIDER_DISABLED'))
        }
        if (!['success', 'partial', 'empty', 'unavailable', 'timeout', 'error'].includes(response?.status)) {
          throw new ResearchWorkflowError(response?.error?.code || 'INVALID_RESPONSE')
        }
        if (response.status === 'unavailable') {
          return fail(new ResearchWorkflowError(response.error?.code || 'RESEARCH_PROVIDER_UNAVAILABLE'))
        }
        if (response.status === 'error' || response.status === 'timeout') {
          throw new ResearchWorkflowError(response.error?.code || 'INVALID_RESPONSE')
        }
        return update({ phase: 'complete', preview: null, previewInput: null, result: response, error: null })
      } catch (error) {
        return fail(error)
      }
    },
  }
}

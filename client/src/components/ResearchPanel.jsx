import { useEffect, useState } from 'react'
import { ArrowLeft, Search, ShieldAlert } from 'lucide-react'
import {
  createResearchWorkflowApi,
  createResearchWorkflowController,
} from '../lib/researchWorkflow.js'
import './ResearchPanel.css'

function ResearchResults({ response }) {
  const sources = Array.isArray(response?.sources) ? response.sources : []
  if (response.status === 'empty' || sources.length === 0) {
    return <p className="research-result-note">The backend returned no source results.</p>
  }

  return (
    <ul className="research-source-list">
      {sources.map((source, index) => (
        <li key={source.id || `${source.url}-${index}`}>
          <a href={source.url} target="_blank" rel="noreferrer noopener">
            {source.title || source.url}
          </a>
          {source.excerpt && <p>{source.excerpt}</p>}
        </li>
      ))}
    </ul>
  )
}

export default function ResearchPanel({ apiUrl, auth, onClose, workflowController }) {
  const [controller] = useState(() => workflowController || createResearchWorkflowController({
    api: createResearchWorkflowApi({ apiUrl, auth }),
  }))
  const [state, setState] = useState(controller.getState())
  const busy = state.phase === 'preparing' || state.phase === 'confirming'

  useEffect(() => controller.subscribe(setState), [controller])

  useEffect(() => {
    if (!state.preview) return undefined
    const expiryTime = Date.parse(state.preview.expiresAt)
    const timeout = setTimeout(() => controller.expire(), Math.max(0, expiryTime - Date.now()))
    return () => clearTimeout(timeout)
  }, [controller, state.preview])

  function handleQueryChange(event) {
    controller.setQuery(event.target.value)
  }

  function handleResultCountChange(event) {
    controller.setMaxResults(Number(event.target.value))
  }

  async function handlePrepare(event) {
    event.preventDefault()
    await controller.prepare()
  }

  async function handleConfirm() {
    await controller.confirm()
  }

  return (
    <section className="research-panel" aria-labelledby="research-panel-title">
      <div className="research-panel-heading">
        <div>
          <p className="research-eyebrow"><Search size={14} /> Public-source Research</p>
          <h2 id="research-panel-title">Review a research query</h2>
        </div>
        <button type="button" className="research-back-button" onClick={onClose} disabled={busy}>
          <ArrowLeft size={15} /> Back to chat
        </button>
      </div>

      <p className="research-privacy-notice">
        Use only questions about public information. Do not include personal data, credentials,
        confidential material, or investigation targets. Screening is limited and cannot detect every
        sensitive query.
      </p>
      <p className="research-offline-notice">
        Preparing shows a preview only. If you confirm, the backend checks your confirmation; this build
        remains offline-only and will not send the query to Tavily.
      </p>

      <form className="research-form" onSubmit={handlePrepare}>
        <label htmlFor="research-query">Research question</label>
        <textarea
          id="research-query"
          value={state.query}
          onChange={handleQueryChange}
          maxLength={1000}
          rows={4}
          disabled={busy}
          placeholder="Ask a general question answerable from public sources"
        />
        <div className="research-form-actions">
          <label htmlFor="research-result-count">Maximum results</label>
          <select
            id="research-result-count"
            value={state.maxResults}
            onChange={handleResultCountChange}
            disabled={busy}
          >
            {[1, 2, 3, 4, 5].map((count) => <option key={count} value={count}>{count}</option>)}
          </select>
          <button type="submit" className="research-primary-button" disabled={busy || !state.query.trim()}>
            {state.phase === 'preparing' ? 'Preparing preview…' : 'Preview query'}
          </button>
        </div>
      </form>

      {state.preview && (
        <section className="research-preview" aria-labelledby="research-preview-title" aria-live="polite">
          <h3 id="research-preview-title">Review before confirming</h3>
          <dl className="research-preview-details">
            <div><dt>Provider</dt><dd>{state.preview.provider}</dd></div>
            <div><dt>Maximum results</dt><dd>{state.preview.maxResults}</dd></div>
            <div>
              <dt>Expires</dt>
              <dd><time dateTime={state.preview.expiresAt}>{new Date(state.preview.expiresAt).toLocaleString()}</time></dd>
            </div>
          </dl>
          <div className="research-preview-query">
            <span>Exact query to review</span>
            <p>{state.preview.query}</p>
          </div>
          <p className="research-confirm-notice">
            Confirming authorizes this exact query for Tavily Research if live access is approved in a
            future stage. External provider access is disabled in this build.
          </p>
          <div className="research-preview-actions">
            <button type="button" className="research-primary-button" onClick={handleConfirm} disabled={busy}>
              {state.phase === 'confirming' ? 'Checking confirmation…' : 'Confirm query'}
            </button>
            <button type="button" className="research-secondary-button" onClick={() => controller.cancel()} disabled={busy}>
              Cancel preview
            </button>
          </div>
        </section>
      )}

      {state.error && (
        <p className={`research-feedback ${state.phase === 'disabled' ? 'research-feedback-disabled' : ''}`} role="alert">
          {state.phase === 'disabled' && <ShieldAlert size={16} />}
          {state.error}
        </p>
      )}

      {state.phase === 'complete' && state.result && (
        <section className="research-results" aria-labelledby="research-results-title" aria-live="polite">
          <h3 id="research-results-title">Research response</h3>
          <ResearchResults response={state.result} />
          {state.result.status === 'partial' && state.result.limitations?.map((item) => <p key={item} className="research-result-note">{item}</p>)}
        </section>
      )}
    </section>
  )
}

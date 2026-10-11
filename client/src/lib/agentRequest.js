export async function fetchAgentRequest(url, options, auth, fetchImpl = fetch) {
  const requestOptions = { ...options, headers: new Headers(options?.headers || {}) }
  let accessToken = null

  if (auth) {
    try {
      const { data, error } = await auth.getSession()
      if (!error) accessToken = data?.session?.access_token || null
    } catch {
      // The backend will return its normal unauthenticated response. Never log
      // session data or turn a local session-read failure into trusted identity.
    }
  }

  if (accessToken) requestOptions.headers.set('Authorization', `Bearer ${accessToken}`)
  let response = await fetchImpl(url, requestOptions)

  if (response.status !== 401 || !accessToken || !auth?.refreshSession) return response

  try {
    const { data, error } = await auth.refreshSession()
    const refreshedToken = !error ? data?.session?.access_token : null
    if (!refreshedToken) return response

    const retryOptions = {
      ...requestOptions,
      headers: new Headers(requestOptions.headers),
    }
    retryOptions.headers.set('Authorization', `Bearer ${refreshedToken}`)
    response = await fetchImpl(url, retryOptions)
  } catch {
    // Keep the original non-sensitive 401 response so the UI can ask the user
    // to sign in again without exposing provider or token details.
  }

  return response
}

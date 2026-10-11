export function subscribeToAuthState(auth, onSession) {
  let active = true
  let authEventReceived = false

  const { data: { subscription } } = auth.onAuthStateChange((_event, session) => {
    authEventReceived = true
    if (active) onSession(session ?? null)
  })

  Promise.resolve()
    .then(() => auth.getSession())
    .then(({ data, error }) => {
      if (active && !authEventReceived) onSession(error ? null : data?.session ?? null)
    })
    .catch(() => {
      if (active && !authEventReceived) onSession(null)
    })

  return () => {
    active = false
    subscription.unsubscribe()
  }
}

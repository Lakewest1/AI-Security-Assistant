import { createClient } from '@supabase/supabase-js'

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL?.trim()
const publishableKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY?.trim()

function isValidSupabaseUrl(value) {
  try {
    const url = new URL(value)
    const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    return (url.protocol === 'https:' || (isLocal && url.protocol === 'http:'))
      && Boolean(url.hostname)
      && !url.username
      && !url.password
      && url.pathname === '/'
      && !url.search
      && !url.hash
  } catch {
    return false
  }
}

function isValidPublishableKey(value) {
  return typeof value === 'string' && /^sb_publishable_[A-Za-z0-9_-]+$/.test(value)
}

const missingOrInvalid = []
if (!isValidSupabaseUrl(supabaseUrl)) missingOrInvalid.push('VITE_SUPABASE_URL')
if (!isValidPublishableKey(publishableKey)) {
  missingOrInvalid.push('VITE_SUPABASE_PUBLISHABLE_KEY')
}

let supabase = null
if (missingOrInvalid.length === 0) {
  try {
    supabase = createClient(supabaseUrl, publishableKey)
  } catch {
    missingOrInvalid.push('Supabase client initialization')
  }
}

if (!supabase && import.meta.env.DEV) {
  console.warn(
    `Supabase client is disabled. Configure valid ${missingOrInvalid.join(' and ')} values to enable it.`,
  )
}

export { supabase }
export const isSupabaseConfigured = supabase !== null

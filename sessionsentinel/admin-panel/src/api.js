const API_URL = (import.meta.env.VITE_API_URL || '').replace(/\/+$/, '')

export async function api(path, options = {}) {
  if (import.meta.env.PROD && !API_URL) {
    throw new Error('The frontend API is not configured. Set VITE_API_URL in Vercel and redeploy.')
  }
  const token = localStorage.getItem('token')
  const response = await fetch(`${API_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  })
  if (response.status === 401 && token) {
    localStorage.removeItem('token')
    window.location.assign('/')
  }
  return response
}

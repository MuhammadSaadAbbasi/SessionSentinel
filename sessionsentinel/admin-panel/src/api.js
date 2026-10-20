export async function api(path, options = {}) {
  const token = localStorage.getItem('token')
  const response = await fetch(path, {
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

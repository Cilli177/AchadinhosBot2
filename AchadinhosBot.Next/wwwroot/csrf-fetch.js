(() => {
  const unsafeMethods = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  const originalFetch = window.fetch.bind(window);
  let tokenPromise;

  const isSameOrigin = (input) => {
    const url = input instanceof Request ? input.url : input;
    try {
      return new URL(url, window.location.origin).origin === window.location.origin;
    } catch {
      return false;
    }
  };

  const getToken = async () => {
    tokenPromise ??= originalFetch('/auth/csrf', { credentials: 'same-origin' })
      .then(async (response) => {
        if (!response.ok) return null;
        const payload = await response.json();
        return payload.token || null;
      })
      .catch(() => null);
    return tokenPromise;
  };

  window.fetch = async (input, init = {}) => {
    const request = input instanceof Request ? input : null;
    const method = (init.method || request?.method || 'GET').toUpperCase();
    if (!unsafeMethods.has(method) || !isSameOrigin(input) ||
        new URL(request?.url || input, window.location.origin).pathname === '/auth/login') {
      return originalFetch(input, init);
    }

    const token = await getToken();
    if (!token) return originalFetch(input, init);

    const headers = new Headers(request?.headers || undefined);
    new Headers(init.headers || undefined).forEach((value, key) => headers.set(key, value));
    if (!headers.has('X-Admin-Key') && !headers.has('X-CSRF-TOKEN')) {
      headers.set('X-CSRF-TOKEN', token);
    }

    return originalFetch(input, { ...init, headers, credentials: init.credentials || request?.credentials || 'same-origin' });
  };
})();

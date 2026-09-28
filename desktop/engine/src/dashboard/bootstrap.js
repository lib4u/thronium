// Served by the active Core alongside the installed sing-box dashboard.
// The API secret arrives only in the fragment; never send it in a request URL.
(() => {
  const params = new URLSearchParams(location.hash.slice(1));
  // The application passes its interface language; a page opened directly
  // follows the browser, then the source language.
  const known = Object.keys(THRONIUM_MESSAGES);
  const pick = code => known.find(k => k.toLowerCase() === code.toLowerCase())
    || known.find(k => k.toLowerCase() === code.toLowerCase().split('-')[0]);
  const language = [params.get('language'), ...(navigator.languages || [])]
    .filter(Boolean)
    .map(pick)
    .find(Boolean) || THRONIUM_SOURCE_LANGUAGE;
  const status = document.getElementById('dashboard-status');
  document.documentElement.lang = language;
  if (document.body.dataset.throniumPage === 'placeholder') {
    status.textContent = THRONIUM_MESSAGES[language].install;
    return;
  }
  status.textContent = THRONIUM_MESSAGES[language].opening;
  const entry = {id: 'thronium', name: 'Thronium', url: location.host, secret: params.get('secret') || ''};
  try { history.replaceState(null, '', location.pathname); } catch (_) {}
  const key = 'sing-box-dashboard.servers';
  let state;
  try { state = JSON.parse(localStorage.getItem(key)); } catch (_) {}
  if (!state || typeof state !== 'object' || Array.isArray(state)) state = {};
  if (!Array.isArray(state.servers)) state.servers = [];
  state.servers = state.servers.filter(server => server && typeof server === 'object' && server.id !== entry.id);
  state.servers.push(entry);
  state.activeId = entry.id;
  try {
    localStorage.setItem(key, JSON.stringify(state));
    location.replace('/dashboard/');
  } catch (_) {
    status.textContent = THRONIUM_MESSAGES[language].storage_failed;
  }
})();

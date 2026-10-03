/** All interpolated backend strings pass through escapeHTML. */
export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[ch]));
export const number = value => Number.isFinite(value) ? value.toLocaleString() : '—';
export function timestamp(value, full = false) {
  if (value === null || value === undefined || value === '') return '—';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  return full ? date.toLocaleString(undefined, {year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'}) : date.toLocaleTimeString(undefined, {hour: '2-digit', minute: '2-digit', second: '2-digit'});
}
export const shortId = value => value ? `${String(value).slice(0, 8)}…${String(value).slice(-4)}` : '—';
export const deviceHref = id => `#devices/${encodeURIComponent(id)}`;
export function sessionState(device, now = Date.now()) {
  if (device.state === 'REVOKED') return {authentication: 'REVOKED', session: 'INVALIDATED', usable: false};
  const session = device.session;
  if (!session || !session.active || !session.authenticated) return {authentication: 'NOT AUTHENTICATED', session: 'NONE', usable: false};
  if (session.expires_at <= now) return {authentication: 'NOT AUTHENTICATED', session: 'EXPIRED', usable: false};
  return {authentication: 'AUTHENTICATED', session: 'VALID', usable: true};
}
export function eventMatches(event, filters, now = Date.now()) {
  if (filters.device && event.device_id !== filters.device) return false;
  if (filters.type && event.event_type !== filters.type) return false;
  if (filters.status && event.status !== filters.status) return false;
  if (filters.window && now - new Date(event.recorded_at).getTime() > Number(filters.window) * 60000) return false;
  return true;
}
export const errorMessage = code => ({
  revoked_device: 'This device is revoked. Commands are disabled.',
  invalid_session: 'No authenticated session. Wait for the device to reconnect.',
  expired_session: 'The session has expired. Wait for reauthentication.',
  invalid_parameters: 'Check the command parameters and supported ranges.',
  command_publish_failed: 'Command publication failed. Check the broker connection.',
  unknown_device: 'The device is not registered.',
  session_state_conflict: 'Device or session state changed. Refresh before trying again.',
  'MQTT control unavailable': 'Command delivery is unavailable. Check the broker connection.',
}[code] || 'The operation could not be completed. Refresh and check backend availability.');


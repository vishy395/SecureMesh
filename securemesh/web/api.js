/** Same-origin requests only. No broker credentials or cryptographic material. */
export async function request(path, {method = 'GET', body, signal} = {}) {
  const timeout = AbortSignal.timeout(10000);
  const response = await fetch(path, {
    method, signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    headers: body === undefined ? {} : {'Content-Type': 'application/json'},
    body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store',
  });
  if (!response.ok) {
    let code = `HTTP ${response.status}`;
    try { const result = await response.json(); if (typeof result.detail === 'string') code = result.detail; } catch { /* Fixed fallback. */ }
    const error = new Error(code); error.status = response.status; throw error;
  }
  return response.json();
}
export const snapshot = (deviceId, signal) => request(`/api/dashboard${deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : ''}`, {signal});
export const sendCommand = (deviceId, commandType, parameters) => request(`/api/devices/${encodeURIComponent(deviceId)}/commands`, {method: 'POST', body: {command_type: commandType, parameters}});
export const revokeDevice = deviceId => request(`/api/devices/${encodeURIComponent(deviceId)}/revoke`, {method: 'POST'});
export const rotateSession = deviceId => request(`/api/devices/${encodeURIComponent(deviceId)}/sessions/rotate`, {method: 'POST'});


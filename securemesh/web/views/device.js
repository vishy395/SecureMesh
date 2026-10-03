import {escapeHTML as e, timestamp, number, shortId, sessionState} from '../format.js';
import {title, status, empty, commandsTable, telemetryTable} from '../components/ui.js';
import {telemetryChart} from '../components/chart.js';
import {eventFeed} from './overview.js';

const definition = items => `<dl class="definition">${items.map(([label,value]) => `<div><dt>${e(label)}</dt><dd>${value}</dd></div>`).join('')}</dl>`;
export function deviceDetail(data,id) {
  const device = data.devices.find(row => row.device_id===id);
  if (!device) return empty('Device unavailable','This device is not registered. Return to the device registry.');
  const auth = sessionState(device,data.generated_at);
  const session = device.session || data.sessions.find(row => row.device_id===id);
  const latest = device.latest_telemetry;
  const reading = latest?.payload;
  const currentState = reading?.device_state;
  const telemetry = data.telemetry.filter(row => row.device_id===id);
  const commands = data.commands.filter(row => row.device_id===id);
  const events = data.events.filter(row => row.device_id===id);
  return title(id,'Identity, session history and the latest accepted device state.',`Registration<strong>${status(device.state)}</strong>`) +
    `<div class="toolbar"><a class="link small" href="#devices">&larr; Device registry</a><button type="button" data-send-device="${e(id)}"${auth.usable?'':' disabled'}>Issue command</button><button type="button" data-rotate="${e(id)}"${auth.usable?'':' disabled'}>Rotate session</button><button type="button" class="danger" data-revoke="${e(id)}"${device.state==='REVOKED'?' disabled':''}>${device.state==='REVOKED'?'Device revoked':'Revoke device'}</button></div>` +
    (device.state==='REVOKED' ? `<div class="notice error">Device revoked at ${e(timestamp(device.revoked_at,true))}. Server admission is disabled; readings below are historical.</div>` : !auth.usable ? '<div class="notice">No authenticated session. Commands are unavailable until the device authenticates.</div>' : '') +
    `<div class="detail-grid"><section><div class="region-head"><h2>Device identity</h2></div>${definition([
      ['Device ID',`<code>${e(id)}</code>`],['Fingerprint',`<code>${e(device.certificate_fingerprint)}</code>`],
      ['Registered',`<time>${e(timestamp(device.registered_at,true))}</time>`],
      ['Certificate',status(device.state==='REVOKED'?'REVOKED':device.certificate_status)],
      ['Certificate expires',`<time>${e(timestamp(device.certificate_valid_until,true))}</time>`],
      ['Revocation',device.revoked_at?`<time>${e(timestamp(device.revoked_at,true))}</time>`:'Not revoked'],
    ])}<p class="audit-note">Certificate status above reflects its validity dates. Role and identity are checked during authentication. No key material is exposed.</p></section><section><div class="region-head"><h2>Authenticated session</h2></div>${session ? definition([
      ['Session ID',`<code>${e(session.session_id)}</code>`],['Authenticated at',`<time>${e(timestamp(session.created_at,true))}</time>`],
      ['Expires',`<time>${e(timestamp(session.expires_at,true))}</time>`],['Status',status(auth.usable?'VALID':device.state==='REVOKED'?'INVALIDATED':session.expires_at<=data.generated_at?'EXPIRED':'INVALIDATED')],
      ['Receive / send',`<code>${e(session.receive_sequence)} / ${e(session.send_sequence)}</code>`],
    ]) : empty('No session history','The device has not completed a handshake.')}<p class="audit-note">Sequence values show the last persisted receive/send state.</p></section></div>` +
    `<section class="region"><div class="region-head"><div><span class="eyebrow">Last accepted ${e(timestamp(latest?.timestamp,true))}</span><h2>Device telemetry</h2></div>${status(currentState?.state || reading?.status?.toUpperCase() || 'NO DATA')}</div>${reading ? `<div class="reading-strip">${[['Temperature',`${number(reading.temperature)} °C`],['Battery',`${number(reading.battery)}%`],['CPU usage',`${number(reading.cpu_usage)}%`],['Threshold',currentState?`${number(currentState.threshold)} °C`:'—']].map(([label,value]) => `<div><span class="small muted">${e(label)}</span><strong>${e(value)}</strong></div>`).join('')}</div>` : ''}${currentState ? definition([
      ['Configuration',`<code>Telemetry ${e(currentState.configuration.telemetry_interval)} s · location ${currentState.configuration.location_enabled?'enabled':'disabled'}</code>`],
      ['Last command',`<code title="${e(currentState.last_command||'')}">${e(currentState.last_command || 'None')}</code>`],
      ['Command sequence',`<code>${e(currentState.last_command_sequence)}</code>`],['Simulated restarts',`<code>${e(currentState.restart_count)}</code>`],
    ]) : ''}${telemetryChart(telemetry.slice(0,60))}${telemetryTable(telemetry.slice(0,15))}</section>` +
    `<section class="region"><div class="region-head"><h2>Recent commands</h2></div>${commandsTable(commands.slice(0,15))}</section>` +
    `<section class="region"><div class="region-head"><h2>Device security events</h2></div>${eventFeed(events.slice(0,15))}</section>`;
}


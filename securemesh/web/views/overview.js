import {escapeHTML as e, timestamp, number, sessionState, deviceHref} from '../format.js';
import {title, status, empty, table} from '../components/ui.js';
import {telemetryChart} from '../components/chart.js';

export function registryTable(devices, compact = false, now = Date.now()) {
  if (!devices.length) return empty('No registered devices', 'Provision a device identity with the existing offline provisioning tool.');
  const headers = compact ? ['Device','Registration','Session','Last seen'] : ['Device','Status','Authentication','Session','Last seen','Telemetry','Commands','Action'];
  const rows = devices.map(device => {
    const auth = sessionState(device,now);
    return `<tr><td class="mono"><a class="table-link" href="${deviceHref(device.device_id)}">${e(device.device_id)}</a></td><td>${status(device.state)}</td>${compact ? '' : `<td>${status(auth.authentication)}</td>`}<td>${status(auth.session)}</td><td class="mono" title="${e(timestamp(device.last_seen,true))}">${e(timestamp(device.last_seen))}</td>${compact ? '' : `<td class="mono">${e(number(device.telemetry_count))}</td><td class="mono">${e(number(device.command_count))}</td><td><a class="link" href="${deviceHref(device.device_id)}">Inspect</a></td>`}</tr>`;
  });
  return table(headers,rows,'Device registry');
}
export function overview(data) {
  const t = data.totals;
  const metrics = [
    ['Total devices',t.total_devices],['Active registrations',t.active_devices],
    ['Authenticated devices',t.authenticated_devices,t.authenticated_devices ? 'good' : ''],
    ['Revoked devices',t.revoked_devices,t.revoked_devices ? 'bad' : ''],
    ['Telemetry received',t.telemetry_received],['Commands issued',t.commands_issued],
    ['Commands executed',t.commands_executed],['Blocked security events',t.blocked_events,t.blocked_events ? 'bad' : ''],
  ];
  return title('Operational overview','Device identity, protected traffic and command delivery in one operational view.',`MQTT transport<strong>${e(data.health.mqtt)}</strong>`) +
    `<div class="metrics" aria-label="Lifetime backend totals">${metrics.map(([label,value,tone]) => `<div class="metric"><div class="metric-label">${e(label)}</div><div class="metric-value ${tone||''}">${e(number(value))}</div></div>`).join('')}</div>` +
    `<section class="region"><div class="region-head"><div><span class="eyebrow">Protected traffic</span><h2>Live telemetry</h2></div><a class="link small" href="#telemetry">Inspect readings &rarr;</a></div>${telemetryChart(data.telemetry.slice(0,100))}</section>` +
    `<div class="split"><section><div class="region-head"><div><span class="eyebrow">Identity & availability</span><h2>Device registry</h2></div><a class="link small" href="#devices">All devices &rarr;</a></div>${registryTable(data.devices,true,data.generated_at)}</section><section><div class="region-head"><div><span class="eyebrow">Audit trail</span><h2>Recent security events</h2></div><a class="link small" href="#security">Inspect &rarr;</a></div>${eventFeed(data.events.slice(0,5))}</section></div>`;
}
export function eventFeed(events) {
  if (!events.length) return empty('No security events', 'Recorded authentication, command and security decisions will appear here.');
  return `<div class="event-list">${events.map(event => `<div class="event-item"><time class="muted">${e(timestamp(event.recorded_at))}</time><div><p>${e(event.event_type.toUpperCase())}</p><small>${e(event.device_id||'System')} · ${e(event.reason)}</small></div>${status(event.status)}</div>`).join('')}</div>`;
}
export function devices(data, ui) {
  const filtered = data.devices.filter(device => (!ui.registryState || device.state===ui.registryState) && device.device_id.toLowerCase().includes(ui.search.toLowerCase()));
  return title('Device registry','Registration state is distinct from authentication and simulator state.') +
    `<div class="toolbar"><div class="field"><label for="search">Find device</label><input id="search" data-key="search" type="search" value="${e(ui.search)}" placeholder="Device ID"></div><div class="field"><label for="registryState">Registration</label><select id="registryState" data-key="registryState"><option value="">All registrations</option>${['ACTIVE','REVOKED'].map(state => `<option${state===ui.registryState?' selected':''}>${state}</option>`).join('')}</select></div><span class="small muted">${filtered.length} of ${data.devices.length} devices</span></div>` +
    (filtered.length ? registryTable(filtered,false,data.generated_at) : empty('No matching devices','Change the device ID or registration filter.'));
}


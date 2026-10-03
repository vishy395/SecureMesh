import {escapeHTML as e, timestamp, number} from '../format.js';
export function status(value) {
  const good = ['ACTIVE', 'AUTHENTICATED', 'VALID', 'EXECUTED', 'ALREADY_PROCESSED', 'RUNNING'];
  const bad = ['REVOKED', 'BLOCKED', 'FAILED', 'REJECTED'];
  const pending = ['CREATED', 'SENT'];
  const tone = good.includes(value) ? 'good' : bad.includes(value) ? 'bad' : pending.includes(value) ? 'pending' : 'neutral';
  return `<span class="status ${tone}">${e(value || 'UNKNOWN')}</span>`;
}
export function empty(title, description) { return `<div class="empty"><span class="eyebrow">No records</span><h2>${e(title)}</h2><p>${e(description)}</p></div>`; }
export function title(heading, description, note = '') { return `<div class="title-row"><div><h1>${e(heading)}</h1><p>${e(description)}</p></div>${note ? `<div class="title-note">${note}</div>` : ''}</div>`; }
export function table(headers, rows, caption, key = caption) {
  return `<div class="table-wrap" data-scroll-key="${e(key)}" tabindex="0" role="region" aria-label="${e(caption)}; scroll horizontally for all columns"><table><caption class="visually-hidden">${e(caption)}</caption><thead><tr>${headers.map(x => `<th scope="col">${e(x)}</th>`).join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}
export function options(items, selected, first = 'All devices') {
  return `<option value="">${e(first)}</option>${items.map(item => `<option value="${e(item)}"${item === selected ? ' selected' : ''}>${e(item)}</option>`).join('')}`;
}
export function fieldSelect(label, key, items, selected, first) {
  return `<div class="field"><label for="${e(key)}">${e(label)}</label><select id="${e(key)}" data-key="${e(key)}">${options(items,selected,first)}</select></div>`;
}
export function commandsTable(commands, compact = false) {
  if (!commands.length) return empty('No commands issued', 'Issue a supported command to an active, authenticated device.');
  const rows = commands.map(row => `<tr><td class="mono"><button type="button" class="quiet command-id" data-command="${e(row.command_id)}" title="${e(row.command_id)}">${e(row.command_id)}</button></td><td class="mono">${e(row.device_id)}</td><td class="mono">${e(row.command_type)}</td><td class="mono">${e(timestamp(row.issued_at))}</td><td>${status(row.status)}</td>${compact ? '' : `<td>${row.acknowledgement ? status(row.acknowledgement.status) : '<span class="muted">Awaiting ACK</span>'}</td><td class="mono">${e(timestamp(row.completed_at))}</td>`}</tr>`);
  return table(compact ? ['Command ID','Target','Command','Issued','Status'] : ['Command ID','Target','Command','Issued','Status','Acknowledgement','Completed'], rows, 'Command history');
}
export function telemetryTable(rows) {
  if (!rows.length) return empty('No telemetry received', 'Authenticated device readings will appear here.');
  return table(['Device','Timestamp','Temperature','Battery','CPU usage','State','Sequence'], rows.map(row => `<tr><td class="mono"><a class="table-link" href="#devices/${encodeURIComponent(row.device_id)}">${e(row.device_id)}</a></td><td class="mono" title="${e(timestamp(row.timestamp,true))}">${e(timestamp(row.timestamp))}</td><td class="mono">${e(number(row.payload.temperature))} °C</td><td class="mono">${e(number(row.payload.battery))}%</td><td class="mono">${e(number(row.payload.cpu_usage))}%</td><td>${status(row.payload.device_state?.state || row.payload.status.toUpperCase())}</td><td class="mono">${e(row.sequence)}</td></tr>`), 'Protected telemetry');
}


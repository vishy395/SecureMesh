import {escapeHTML as e, sessionState, timestamp} from '../format.js';
import {title, status, options, commandsTable, empty} from '../components/ui.js';
export const commandKinds = ['START','STOP','RESTART','CHANGE_THRESHOLD','UPDATE_CONFIG'];
export function commandParameters(draft) {
  if (draft.kind==='CHANGE_THRESHOLD') return {threshold:Number(draft.threshold)};
  if (draft.kind==='UPDATE_CONFIG') {
    const params={};
    if (draft.applyInterval) params.telemetry_interval=Number(draft.interval);
    if (draft.applyLocation) params.location_enabled=draft.location==='true';
    return params;
  }
  return {};
}
export function commands(data,ui) {
  const draft=ui.command;
  const device=data.devices.find(row=>row.device_id===draft.device);
  const auth=device?sessionState(device,data.generated_at):{usable:false};
  const selected=data.commands.find(row=>row.command_id===ui.selectedCommand);
  const available=data.health.mqtt==='connected' && auth.usable;
  const rows=data.commands.filter(row=>!ui.commandHistoryDevice||row.device_id===ui.commandHistoryDevice);
  let params='';
  if (draft.kind==='CHANGE_THRESHOLD') params=`<div class="field"><label for="threshold">Threshold (°C)</label><input id="threshold" data-key="command.threshold" type="number" min="-100" max="200" step="any" required value="${e(draft.threshold)}"></div><p>Supported range: -100 to 200 °C.</p>`;
  if (draft.kind==='UPDATE_CONFIG') params=`<label class="check-row"><input type="checkbox" data-key="command.applyInterval"${draft.applyInterval?' checked':''}>Change telemetry interval</label><div class="field"><label for="interval">Telemetry interval (seconds)</label><input id="interval" data-key="command.interval" type="number" min="0.1" max="3600" step="any" value="${e(draft.interval)}"${draft.applyInterval?' required':' disabled'}></div><label class="check-row"><input type="checkbox" data-key="command.applyLocation"${draft.applyLocation?' checked':''}>Change location reporting</label><div class="field"><label for="location">Location reporting</label><select id="location" data-key="command.location"${draft.applyLocation?'':' disabled'}><option value="true"${draft.location==='true'?' selected':''}>Enabled</option><option value="false"${draft.location==='false'?' selected':''}>Disabled</option></select></div><p>Only selected configuration fields will change.</p>`;
  return title('Command center','Issue supported operations through an authenticated device session.') +
    `<div class="command-layout"><form id="command-form" class="command-form"><span class="eyebrow">Protected command delivery</span><h2>Issue command</h2><div class="field"><label for="commandDevice">Target device</label><select id="commandDevice" data-key="command.device" required>${options(data.devices.map(row=>row.device_id),draft.device,'Select a device')}</select></div><div class="field"><label for="commandKind">Command</label><select id="commandKind" data-key="command.kind">${commandKinds.map(kind=>`<option${kind===draft.kind?' selected':''}>${kind}</option>`).join('')}</select></div>${params}<div class="command-summary">${device ? `${status(device.state)}<br>${status(auth.usable?'AUTHENTICATED':'UNAVAILABLE')}` : 'Select a target to check command availability.'}</div><p class="audit-note">${device?.state==='REVOKED'?'Revoked devices cannot receive commands.':data.health.mqtt!=='connected'?'Command delivery is unavailable while MQTT is disconnected.':!auth.usable?'An active registration and authenticated session are required.':'The device validates the command before execution.'}</p><button id="review-command" type="submit" class="primary"${available&&!ui.busy?'':' disabled'}>${ui.busy?'Sending…':'Review command \u2192'}</button></form><section><div class="region-head"><div><span class="eyebrow">Delivery & acknowledgement</span><h2>Command history</h2></div></div>${selected ? `<div class="command-selected"><div class="region-head"><h3>${e(selected.command_type)} · ${e(selected.device_id)}</h3>${status(selected.status)}</div><p><code>${e(selected.command_id)}</code></p><p class="small muted">Issued ${e(timestamp(selected.issued_at,true))} · expires ${e(timestamp(selected.expires_at,true))}</p><p class="audit-note">${selected.acknowledgement?`Acknowledgement: ${e(selected.acknowledgement.status)} at ${e(timestamp(selected.acknowledgement.timestamp,true))} · command sequence ${e(selected.acknowledgement.command_sequence)}`:'Awaiting an authenticated acknowledgement.'}</p><p class="audit-note">Completed: ${e(timestamp(selected.completed_at,true))}</p></div>` : ''}<div class="toolbar"><div class="field"><label for="commandHistoryDevice">Target filter</label><select id="commandHistoryDevice" data-key="commandHistoryDevice">${options(data.devices.map(row=>row.device_id),ui.commandHistoryDevice,'All devices')}</select></div><span class="small muted">Latest ${data.history_limit} commands</span></div>${commandsTable(rows)}<p class="audit-note">An expired command may have executed without a received acknowledgement. Check device state before issuing another command.</p></section></div>`;
}


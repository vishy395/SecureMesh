import {escapeHTML as e} from '../format.js';
import {title, fieldSelect, telemetryTable} from '../components/ui.js';
import {telemetryChart} from '../components/chart.js';
export function telemetry(data,ui) {
  const rows = data.telemetry.filter(row => !ui.telemetryDevice || row.device_id===ui.telemetryDevice);
  return title('Protected telemetry','Readings accepted after authentication, replay protection and freshness validation.') +
    `<div class="toolbar">${fieldSelect('Device','telemetryDevice',data.devices.map(row=>row.device_id),ui.telemetryDevice,'All devices')}<span class="small muted">Recent ${data.history_limit}-message window · ${rows.length} matching readings</span></div>` +
    `<section class="region">${telemetryChart(rows)}</section>` + telemetryTable(rows);
}


import {escapeHTML as e, timestamp} from '../format.js';
import {empty} from './ui.js';

/** Only real samples; no padding or fabricated readings. */
export function telemetryChart(rows) {
  const ordered = [...rows].filter(row => Number.isFinite(row.payload.temperature)).sort((a,b) => a.timestamp-b.timestamp);
  if (!ordered.length) return empty('No telemetry to plot', 'The temperature timeline starts with the first authenticated reading.');
  const devices = [...new Set(ordered.map(row => row.device_id))].sort();
  const width = window.innerWidth < 760 ? Math.max(300, window.innerWidth - 64) : 920;
  const right = width - 32;
  const start = ordered[0].timestamp, end = ordered.at(-1).timestamp;
  const values = ordered.map(row => row.payload.temperature);
  const low = Math.floor(Math.min(...values)-1), high = Math.ceil(Math.max(...values)+1);
  const x = time => 48 + (end === start ? 0.5 : (time-start)/(end-start))*(width-80);
  const y = value => 145 - (value-low)/(high-low)*120;
  const lines = devices.map((device,index) => {
    const samples = ordered.filter(row => row.device_id === device);
    return `<polyline class="series-${index%3}" points="${samples.map(row => `${x(row.timestamp)},${y(row.payload.temperature)}`).join(' ')}"/>${samples.length === 1 ? `<circle cx="${x(samples[0].timestamp)}" cy="${y(samples[0].payload.temperature)}" r="3"/>` : ''}`;
  }).join('');
  return `<div class="chart-region"><div class="chart-meta"><span class="small muted">Temperature / °C</span><div class="legend">${devices.map((id,index) => `<span><i class="series-${index%3}" aria-hidden="true"></i>${e(id)}</span>`).join('')}</div></div><svg class="chart" viewBox="0 0 ${width} 180" role="img" aria-label="Temperature timeline for ${e(devices.join(', '))}; ${ordered.length} actual readings from ${e(timestamp(start))} to ${e(timestamp(end))}"><line class="gridline" x1="48" x2="${right}" y1="25" y2="25"/><line class="gridline" x1="48" x2="${right}" y1="85" y2="85"/><line class="gridline" x1="48" x2="${right}" y1="145" y2="145"/><text x="0" y="29">${high}°</text><text x="0" y="89">${((high+low)/2).toFixed(1)}°</text><text x="0" y="149">${low}°</text>${lines}<text x="48" y="175">${e(timestamp(start))}</text><text x="${right}" y="175" text-anchor="end">${e(timestamp(end))}</text></svg><p class="chart-caption">${ordered.length} received ${ordered.length===1?'reading':'readings'} · latest retained window · exact values in the telemetry table</p></div>`;
}


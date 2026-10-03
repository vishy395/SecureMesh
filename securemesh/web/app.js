import {createStore} from './store.js';
import {sendCommand,revokeDevice,rotateSession} from './api.js';
import {escapeHTML as e, timestamp, errorMessage} from './format.js';
import {empty} from './components/ui.js';
import {overview,devices} from './views/overview.js';
import {deviceDetail} from './views/device.js';
import {telemetry} from './views/telemetry.js';
import {commands,commandParameters} from './views/commands.js';
import {security} from './views/security.js';

const store=createStore();
const view=document.querySelector('#view');
const ui={search:'',registryState:'',telemetryDevice:'',eventType:'',eventDevice:'',eventStatus:'',eventWindow:'',commandHistoryDevice:'',selectedCommand:'',busy:false,
  command:{device:'',kind:'START',threshold:'35',interval:'2',location:'true',applyInterval:true,applyLocation:false}};
let route={view:'overview',device:null};
let message=null;
const names={overview:'Overview',devices:'Devices',telemetry:'Telemetry',commands:'Command center',security:'Security events'};
function readRoute() {
  const parts=(location.hash.slice(1)||'overview').split('/');
  route={view:names[parts[0]]?parts[0]:'overview',device:null};
  if(route.view==='devices' && parts[1]) { try {route.device=decodeURIComponent(parts[1]);} catch {route.device=null;} }
  store.setScope(route.device);
  render(store.state);
}
function render(state) {
  const focused=document.activeElement;
  const focusKey=focused?.dataset?.key;
  const focusAttributes=view.contains(focused) ? ['id','href','data-command','data-revoke','data-rotate','data-send-device','data-scroll-key'].map(key=>[key,focused.getAttribute(key)]).filter(([,value])=>value!==null) : [];
  const selection=focused instanceof HTMLInputElement && ['text','search'].includes(focused.type) ? [focused.selectionStart,focused.selectionEnd] : null;
  const scrolls=[...view.querySelectorAll('[data-scroll-key]')].map(el=>[el.dataset.scrollKey,el.scrollLeft]);
  if(message?.commandId && state.data) {
    const command=state.data.commands.find(row=>row.command_id===message.commandId);
    if(command?.acknowledgement) {
      message={...message,text:`${command.device_id}: ${command.command_type} acknowledged ${command.acknowledgement.status}.`,error:['FAILED','REJECTED'].includes(command.status)};
    } else if(command && ['EXPIRED','FAILED'].includes(command.status)) {
      message={...message,text:`Command ${command.status.toLowerCase()}. Check device state and command history before retrying.`,error:true};
    }
  }
  let html;
  if(!state.data) html=state.error?empty(state.error==='This device is not registered.'?'Device unavailable':'Control center unavailable',state.error):'<div class="empty" role="status"><span class="eyebrow">Reading backend</span><h2>Loading operational data</h2><p>Waiting for registry and message history.</p></div>';
  else if(route.device) html=deviceDetail(state.data,route.device);
  else html=({overview,devices,telemetry,commands,security}[route.view])(state.data,ui);
  view.innerHTML=html;
  if(focusKey || focusAttributes.length) {
    const target=focusKey ? [...view.querySelectorAll('[data-key]')].find(el=>el.dataset.key===focusKey) : [...view.querySelectorAll('a,button,input,select,[tabindex]')].find(el=>focusAttributes.every(([key,value])=>el.getAttribute(key)===value));
    if(target) {target.focus({preventScroll:true});if(selection)target.setSelectionRange(...selection);}
  }
  for(const [key,left] of scrolls) {const el=[...view.querySelectorAll('[data-scroll-key]')].find(x=>x.dataset.scrollKey===key);if(el)el.scrollLeft=left;}
  document.querySelectorAll('[data-nav]').forEach(link=>{if(link.dataset.nav===route.view)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');});
  document.querySelector('#breadcrumb').textContent=`Operations / ${names[route.view]}${route.device?` / ${route.device}`:''}`;
  document.title=`${route.device||names[route.view]} · SecureMesh`;
  const connection=document.querySelector('#connection');
  const broker=state.data?.health.mqtt;
  const connectionHTML=state.error==='This device is not registered.'?'<span class="indicator"></span>Device unavailable':state.error?'<span class="indicator failed"></span>Backend disconnected':!state.data?'<span class="indicator"></span>Connecting':broker==='connected'?'<span class="indicator healthy"></span>System connected':`<span class="indicator"></span>MQTT ${e(broker)}`;
  if(connection.innerHTML!==connectionHTML)connection.innerHTML=connectionHTML;
  document.querySelector('#sync').textContent=state.refreshedAt?`Updated ${timestamp(state.refreshedAt)} · ${state.error?'reconnecting':'5 s refresh'}`:'Waiting for backend';
  const noticeHTML=state.error?`<div class="notice error">${e(state.error)} <button type="button" data-retry>Retry</button></div>`:message?`<div class="notice ${message.error?'error':'success'}">${e(message.text)} <button type="button" data-dismiss class="quiet" aria-label="Dismiss notification">Dismiss</button></div>`:'';
  const notice=document.querySelector('#notice');
  if(notice.innerHTML!==noticeHTML)notice.innerHTML=noticeHTML;
}
async function confirm(title,description,danger=false) {
  const dialog=document.querySelector('#confirm');
  document.querySelector('#confirm-title').textContent=title;
  document.querySelector('#confirm-description').textContent=description;
  document.querySelector('#confirm-action').className=danger?'danger':'primary';
  dialog.returnValue='cancel';
  dialog.showModal();
  return new Promise(resolve=>dialog.addEventListener('close',()=>resolve(dialog.returnValue==='confirm'),{once:true}));
}
async function mutate(action,success) {
  if(ui.busy)return;
  ui.busy=true;message=null;render(store.state);
  try {const result=await action();message={text:success};if(result.command_id){ui.selectedCommand=result.command_id;message.commandId=result.command_id;}await store.refresh();}
  catch(error) {message={text:errorMessage(error.message),error:true};}
  finally {ui.busy=false;render(store.state);}
}
view.addEventListener('input',event=>{
  const target=event.target,key=target.dataset.key;
  if(!key)return;
  const value=target.type==='checkbox'?target.checked:target.value;
  if(key.startsWith('command.'))ui.command[key.slice(8)]=value;else ui[key]=value;
  if(target.tagName==='SELECT'||target.type==='checkbox'||key==='search')render(store.state);
});
view.addEventListener('submit',async event=>{
  if(event.target.id!=='command-form')return;
  event.preventDefault();
  const draft={...ui.command};
  const parameters=commandParameters(draft);
  if(draft.kind==='UPDATE_CONFIG'&&!Object.keys(parameters).length){message={text:'Select at least one supported configuration field.',error:true};render(store.state);return;}
  if(!draft.device||ui.busy)return;
  const descriptions={START:'Set the simulator to RUNNING.',STOP:'Set the simulator to STOPPED. Heartbeat telemetry will continue.',RESTART:'Simulate a restart and establish a fresh authenticated session.',CHANGE_THRESHOLD:`Set the threshold to ${parameters.threshold} °C.`,UPDATE_CONFIG:`Update ${Object.keys(parameters).map(key=>key==='telemetry_interval'?'telemetry interval':'location reporting').join(' and ')}.`};
  if(await confirm(`${draft.kind} · ${draft.device}`,descriptions[draft.kind]))await mutate(()=>sendCommand(draft.device,draft.kind,parameters),'Command sent. Waiting for an authenticated acknowledgement.');
});
view.addEventListener('click',async event=>{
  const button=event.target.closest('button');if(!button||button.disabled)return;
  if(button.dataset.command){ui.selectedCommand=button.dataset.command;if(route.view!=='commands')location.hash='commands';else render(store.state);return;}
  if(button.dataset.sendDevice){ui.command.device=button.dataset.sendDevice;location.hash='commands';return;}
  if(button.dataset.revoke){const id=button.dataset.revoke;if(await confirm(`Revoke ${id}?`,'This permanently revokes the device registration and invalidates its sessions. Telemetry and commands will be rejected.',true))await mutate(()=>revokeDevice(id),`${id} revoked. Sessions invalidated.`);return;}
  if(button.dataset.rotate){const id=button.dataset.rotate;if(await confirm(`Rotate ${id} session?`,'Invalidate the current session and request a fresh authenticated handshake. Commands may be briefly unavailable.'))await mutate(()=>rotateSession(id),`Session rotation requested for ${id}.`);}
});
document.querySelector('#refresh').addEventListener('click',()=>store.refresh());
document.querySelector('#notice').addEventListener('click',event=>{if(event.target.closest('[data-retry]'))store.refresh();if(event.target.closest('[data-dismiss]')){message=null;render(store.state);}});
window.addEventListener('hashchange',readRoute);
let resizeTimer;
window.addEventListener('resize',()=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(()=>render(store.state),120);});
const updateClock=()=>document.querySelector('#clock').textContent=new Date().toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit',second:'2-digit',hour12:false});
updateClock();setInterval(updateClock,1000);
store.subscribe(render);readRoute();store.start();


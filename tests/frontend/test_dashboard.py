import json
from playwright.sync_api import expect
from securemesh.security.identity import certificate_pem


def test_empty_views_and_keyboard_navigation(page,dashboard_server):
    page.goto(dashboard_server[0])
    expect(page.get_by_role('heading',name='Operational overview')).to_be_visible()
    assert page.locator('.metric-value').all_text_contents()==['0']*8
    page.keyboard.press('Tab')
    expect(page.locator('.skip')).to_be_focused()
    page.keyboard.press('Enter')
    expect(page.locator('#main')).to_be_focused()
    expect(page.get_by_text('No telemetry to plot')).to_be_visible()
    for label,heading in [('Devices','Device registry'),('Telemetry','Protected telemetry'),('Command center','Command center'),('Security events','Security events')]:
        page.get_by_role('navigation').get_by_role('link',name=label).click()
        expect(page.get_by_role('heading',name=heading,exact=True)).to_be_visible()
    expect(page.get_by_role('heading',name='No security events')).to_be_visible()
    page.keyboard.press('Tab')
    assert page.evaluate('document.activeElement !== document.body')


def test_data_mapping_revocation_and_security(page,dashboard_server,identity):
    url,repo=dashboard_server
    repo.register_device('device-01','f'*64,certificate_pem(identity[3]).decode())
    repo.record_event('invalid_signature','device-01','a'*32)
    page.goto(url+'/#devices')
    expect(page.get_by_role('link',name='device-01',exact=True)).to_be_visible()
    page.get_by_role('link',name='device-01',exact=True).click()
    expect(page.get_by_role('heading',name='device-01',exact=True)).to_be_visible()
    expect(page.get_by_text('f'*64,exact=True)).to_be_visible()
    page.get_by_role('button',name='Revoke device',exact=True).click()
    expect(page.get_by_role('dialog')).to_be_visible()
    page.get_by_role('dialog').get_by_role('button',name='Cancel').click()
    assert repo.get_device('device-01')['revoked_at'] is None
    page.get_by_role('button',name='Revoke device',exact=True).click()
    page.get_by_role('dialog').get_by_role('button',name='Confirm').click()
    expect(page.get_by_role('button',name='Device revoked',exact=True)).to_be_disabled()
    page.get_by_role('navigation').get_by_role('link',name='Security events').click()
    expect(page.get_by_text('INVALID_SIGNATURE',exact=True)).to_be_visible()
    expect(page.get_by_role('table').get_by_text('BLOCKED',exact=True)).to_be_visible()
    page.locator('#eventStatus').select_option('ACCEPTED')
    expect(page.get_by_text('DEVICE_REVOCATION',exact=True)).to_be_visible()
    expect(page.get_by_text('INVALID_SIGNATURE',exact=True)).to_have_count(0)


def test_frontend_domain_mapping_and_escaping(page,dashboard_server):
    page.goto(dashboard_server[0])
    result=page.evaluate("""async () => {
      const f=await import('/assets/format.js');
      const c=await import('/assets/views/commands.js');
      return {escaped:f.escapeHTML('<img onerror="bad">'),
        revoked:f.sessionState({state:'REVOKED',session:{active:1,authenticated:1,expires_at:Date.now()+1000}}),
        threshold:c.commandParameters({kind:'CHANGE_THRESHOLD',threshold:'35.5'}),
        config:c.commandParameters({kind:'UPDATE_CONFIG',applyInterval:true,interval:'1',applyLocation:true,location:'false'}),
        filter:f.eventMatches({status:'BLOCKED',device_id:'device-01',event_type:'replay_attempt',recorded_at:new Date().toISOString()}, {device:'device-02'})};
    }""")
    assert '<img' not in result['escaped']
    assert result['revoked']['usable'] is False
    assert result['threshold']=={'threshold':35.5}
    assert result['config']=={'telemetry_interval':1,'location_enabled':False}
    assert result['filter'] is False


def test_disconnected_backend_has_retry_and_stale_notice(page,dashboard_server):
    page.goto(dashboard_server[0])
    expect(page.get_by_role('heading',name='Operational overview')).to_be_visible()
    page.route('**/api/dashboard',lambda route:route.abort())
    page.get_by_role('button',name='Refresh',exact=True).click()
    expect(page.get_by_text('Backend disconnected',exact=True)).to_be_visible()
    expect(page.get_by_role('button',name='Retry',exact=True)).to_be_visible()
    expect(page.get_by_role('heading',name='Operational overview')).to_be_visible()


def test_missing_device_and_mobile_layout(page,dashboard_server):
    page.set_viewport_size({'width':390,'height':844})
    page.goto(dashboard_server[0]+'/#devices/missing')
    expect(page.get_by_text('This device is not registered.',exact=True)).to_be_visible()
    assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')


def test_initial_backend_failure_is_actionable(page,dashboard_server):
    page.route('**/api/dashboard',lambda route:route.fulfill(status=503,json={'detail':'unavailable'}))
    page.goto(dashboard_server[0])
    expect(page.get_by_role('heading',name='Control center unavailable')).to_be_visible()
    expect(page.get_by_role('button',name='Retry',exact=True)).to_be_visible()


def test_backend_event_strings_cannot_inject_html(page,dashboard_server):
    attack='<img src=x onerror="window.injected=true">'
    dashboard_server[1].record_event(attack)
    page.goto(dashboard_server[0]+'/#security')
    expect(page.get_by_role('table').get_by_text(attack.upper(),exact=True)).to_be_visible()
    assert page.locator('img').count()==0
    assert page.evaluate('window.injected===undefined')


def test_scope_changes_discard_late_responses(page,dashboard_server):
    page.goto(dashboard_server[0])
    result=page.evaluate("""async () => {
      const {createStore}=await import('/assets/store.js');
      const pending=[];
      const store=createStore(scope=>new Promise(resolve=>pending.push({scope,resolve})));
      store.start();
      store.setScope('device-02');
      pending[1].resolve({scope:'device-02'});
      await new Promise(resolve=>setTimeout(resolve,0));
      pending[0].resolve({scope:'old'});
      await new Promise(resolve=>setTimeout(resolve,0));
      const scope=store.state.data.scope;
      store.stop();
      return scope;
    }""")
    assert result=='device-02'


def test_form_draft_and_keyboard_focus_survive_refresh(page,dashboard_server):
    page.goto(dashboard_server[0]+'/#commands')
    expect(page.get_by_role('heading',name='Command center',exact=True)).to_be_visible()
    page.locator('#commandKind').select_option('CHANGE_THRESHOLD')
    page.locator('#threshold').fill('12.25')
    with page.expect_response('**/api/dashboard'):
        page.evaluate("document.querySelector('#refresh').click()")
    expect(page.locator('#threshold')).to_have_value('12.25')
    expect(page.locator('#threshold')).to_be_focused()


def test_single_reading_is_a_point_not_synthetic_series(page,dashboard_server,identity):
    import time
    url,repo=dashboard_server
    repo.register_device('device-01','f'*64,certificate_pem(identity[3]).decode())
    now=int(time.time()*1000)
    reading={'version':1,'temperature':25.5,'battery':80,'cpu_usage':10,'status':'running','timestamp':now}
    with repo._connection() as db:
        db.execute('INSERT INTO telemetry (device_id,session_id,sequence,timestamp,received_at,payload) VALUES (?,?,?,?,?,?)',('device-01','a'*32,1,now,now,json.dumps(reading)))
    page.goto(url+'/#telemetry')
    expect(page.get_by_role('heading',name='Protected telemetry',exact=True)).to_be_visible()
    assert page.locator('.chart circle').count()==1
    expect(page.get_by_text('1 received reading',exact=False)).to_be_visible()
    assert page.get_by_role('table').locator('tbody tr').count()==1

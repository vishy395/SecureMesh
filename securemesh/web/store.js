import {snapshot} from './api.js';

/** One non-overlapping five-second snapshot request, paused in hidden tabs. */
export function createStore(load = snapshot) {
  let state = {data: null, loading: true, error: null, refreshedAt: null};
  let scope = null, timer = null, running = false, controller = null, generation = 0, failures = 0;
  const subscribers = new Set();
  const publish = next => { state = {...state, ...next}; subscribers.forEach(fn => fn(state)); };
  async function refresh() {
    clearTimeout(timer);
    controller?.abort();
    controller = new AbortController();
    const current = ++generation;
    if (!state.data) publish({loading: true});
    try {
      const data = await load(scope, controller.signal);
      if (current !== generation) return;
      failures = 0;
      publish({data, loading: false, error: null, refreshedAt: Date.now()});
    } catch (error) {
      if (current !== generation) return;
      failures += 1;
      publish({loading: false, error: error.message === 'unknown_device' ? 'This device is not registered.' : 'Backend unavailable. Displayed data may be stale.'});
    } finally {
      if (current === generation && running && !document.hidden) timer = setTimeout(refresh, Math.min(5000 * 2 ** failures, 30000));
    }
  }
  function visibility() {
    clearTimeout(timer);
    if (document.hidden) { controller?.abort(); generation += 1; }
    else if (running) refresh();
  }
  return {
    get state() { return state; },
    subscribe(fn) { subscribers.add(fn); return () => subscribers.delete(fn); },
    refresh,
    setScope(deviceId) {
      if (scope === deviceId) return;
      scope = deviceId;
      publish({data: null, loading: true, error: null});
      if (running) refresh();
    },
    start() { running = true; document.addEventListener('visibilitychange', visibility); refresh(); },
    stop() { running = false; clearTimeout(timer); controller?.abort(); generation += 1; document.removeEventListener('visibilitychange', visibility); },
  };
}


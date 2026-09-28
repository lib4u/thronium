import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

// Execute production hooks with controlled effect lifetimes and IPC promises.
export function hookHarness(path, name, dependencies, args = []) {
  const slots = [], timers = new Map();
  let cursor = 0, nextTimer = 0, pending = [], value;
  const same = (a, b) => a && b && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));
  const react = {
    useState(initial) {
      const index = cursor++;
      slots[index] ??= { value: typeof initial === 'function' ? initial() : initial };
      return [slots[index].value, next => { slots[index].value = typeof next === 'function' ? next(slots[index].value) : next; }];
    },
    useRef(initial) { const index = cursor++; slots[index] ??= { current: initial }; return slots[index]; },
    useCallback(callback, deps) {
      const index = cursor++;
      if (!same(slots[index]?.deps, deps)) slots[index] = { value: callback, deps };
      return slots[index].value;
    },
    useEffect(setup, deps) {
      const index = cursor++;
      const previous = slots[index];
      if (!same(previous?.deps, deps)) {
        const effect = { setup, deps };
        slots[index] = effect;
        pending.push(() => { previous?.cleanup?.(); effect.cleanup = setup(); });
      }
    },
  };
  const exports = {};
  const js = ts.transpileModule(fs.readFileSync(path, 'utf8'), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  vm.runInNewContext(js, { exports, require: key => {
    if (key === 'react') return react;
    if (key in dependencies) return dependencies[key];
    throw new Error(`Unexpected hook dependency: ${key}`);
  }, setTimeout: callback => { const id = ++nextTimer; timers.set(id, callback); return id; },
  clearTimeout: id => timers.delete(id) });
  function render() {
    cursor = 0; pending = []; value = exports[name](...args);
    pending.forEach(effect => effect());
    return value;
  }
  return { render, get value() { return value; }, timers,
    replay() { slots.filter(slot => slot.setup).forEach(effect => { effect.cleanup?.(); effect.cleanup = effect.setup(); }); },
    unmount() { slots.filter(slot => slot.setup).forEach(effect => effect.cleanup?.()); },
    tick() { const [id, callback] = timers.entries().next().value; timers.delete(id); callback(); },
  };
}
export const deferred = () => { let resolve, reject; const promise = new Promise((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; };
export const settle = async () => { for (let i = 0; i < 12; i++) await Promise.resolve(); };

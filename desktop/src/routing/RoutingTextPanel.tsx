import { Textarea, Button } from '../shared/ui/controls';
import { Targets, type W } from './RuleEditor';
import type { RoutingPageController } from './useRoutingPage';

/** Text views of the active profile: simple rule lists per target and raw route JSON. */
export default function RoutingTextPanel({ controller }: { controller: RoutingPageController }) {
  const {
    snapshot,
    tr,
    tab,
    busy,
    simpleTarget,
    setSimpleTarget,
    text,
    buffers,
    setBuffers,
    bufferKey,
    setNotice,
    jsonAction,
    readOnly,
  } = controller;
  return (
    <section className="feature-panel">
      <div className="feature-panel-head">
        <div>
          <h2>{tr(tab as W)}</h2>
          <p>
            {tr(
              tab === 'simple'
                ? 'simpleHint'
                : tab === 'sets'
                  ? 'setsHint'
                  : tab === 'dns'
                    ? 'dnsHint'
                    : 'rawHint',
            )}
          </p>
        </div>
      </div>
      {tab === 'simple' && (
        <div className="route-simple-target">
          <Targets
            tr={tr}
            profiles={snapshot.profiles}
            value={simpleTarget}
            block
            disabled={busy}
            changed={setSimpleTarget}
          />
        </div>
      )}
      <Textarea
        id={tab === 'simple' ? 'simple-rules' : 'route-json'}
        className="text-input desktop-json mono routing-json"
        aria-label={tr(tab as W)}
        spellCheck={false}
        value={text}
        disabled={busy}
        readOnly={readOnly}
        onChange={(e) => {
          setBuffers((old) => ({ ...old, [bufferKey]: e.target.value }));
          setNotice('');
        }}
      />
      {!readOnly && (
        <div className="settings-save">
          <span>
            {buffers[bufferKey] !== undefined ? tr('unsaved') : tab === 'simple' ? tr('simpleOnly') : ''}
          </span>
          <Button
            className="button secondary"
            id="route-json-check"
            disabled={busy}
            onClick={() => void jsonAction(false)}
          >
            {tr('check')}
          </Button>
          <Button
            className="button primary"
            id="route-json-save"
            disabled={busy}
            onClick={() => void jsonAction(true)}
          >
            {tr(tab === 'simple' ? 'simpleSave' : 'save')}
          </Button>
        </div>
      )}
    </section>
  );
}

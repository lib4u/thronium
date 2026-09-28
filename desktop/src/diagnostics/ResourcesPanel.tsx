import { Button } from '../shared/ui/controls';
import { formatPercent } from '../shared/i18n/format.ts';
import { translate, type Language } from '../shared/i18n/index.ts';
import { useEffect, useState } from 'react';
import { command } from '../api';
import { bytes } from '../groups/messages';
import { label, type Label } from '../profiles/schema';
import {
  appendResourcePoint,
  resourcePaths,
  skippedSample,
  type ProcessUsage,
  type ResourcePoint,
  type ResourceSnapshot,
} from './resources';
import './ResourcesPanel.css';

const messageKeys = {
  title: 'diagnostics.cpu_and_memory_aea1e52',
  app: 'diagnostics.application_c79eec6',
  core: 'diagnostics.core_17e16aa',
  hint: 'diagnostics.application_includes_its_helper_processes_the_co_5708368',
  scope: 'diagnostics.cpu_100_is_the_capacity_of_all_logical_processor_27202c7',
  pause: 'diagnostics.pause_updates_e7a6848',
  resume: 'diagnostics.resume_updates_53eab40',
  live: 'diagnostics.updating_every_second_fb7f77e',
  paused: 'diagnostics.updates_paused_2d72a87',
  unsupported: 'diagnostics.process_metrics_are_currently_available_on_linux_24ab1d8',
  unavailable: 'diagnostics.could_not_read_process_metrics_5732e24',
  partial: 'diagnostics.some_processes_could_not_be_measured_values_are__c85230d',
  inactive: 'diagnostics.core_is_not_running_1082565',
  baseline: 'diagnostics.collecting_cpu_sample_fd536a6',
  minute: 'diagnostics.last_minute_while_this_page_is_open_b574f94',
  cpu: 'diagnostics.cpu_load_967a722',
  ram: 'diagnostics.memory_7817861',
  approx: 'diagnostics.at_least_333eedf',
} satisfies Record<string, Label>;

export default function ResourcesPanel({ language }: { language: Language }) {
  const t = (key: keyof typeof messageKeys) => label(messageKeys[key], language);
  const [snapshot, setSnapshot] = useState<ResourceSnapshot | null>(null);
  const [history, setHistory] = useState<ResourcePoint[]>([]);
  const [paused, setPaused] = useState(false);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let generation = 0;
    let busy = false;
    let reset = true;
    let previousCore: string | null = null;
    if (!paused) {
      setSnapshot(null);
      setHistory([]);
      setFailed(false);
    }
    const poll = async () => {
      if (stopped || paused || document.hidden || busy) return;
      busy = true;
      const requestGeneration = generation;
      try {
        const next = await command('processMetrics', { reset });
        if (!stopped && requestGeneration === generation && !document.hidden) {
          setSnapshot(next);
          setFailed(false);
          const changed = next.coreInstance !== previousCore;
          setHistory((old) => appendResourcePoint(old, next, performance.now(), changed));
          previousCore = next.coreInstance;
          reset = false;
        }
      } catch (error) {
        if (!stopped && requestGeneration === generation && !skippedSample(error)) {
          setFailed(true);
          setSnapshot(null);
          setHistory([]);
          reset = true;
        }
      } finally {
        busy = false;
        if (!stopped && !paused && !document.hidden) timer = setTimeout(() => void poll(), 1000);
      }
    };
    const visibility = () => {
      // Paused figures stay as they are when the window hides and returns.
      if (paused) return;
      generation++;
      clearTimeout(timer);
      reset = true;
      setSnapshot(null);
      setHistory([]);
      setFailed(false);
      if (!document.hidden) void poll();
    };
    document.addEventListener('visibilitychange', visibility);
    if (!paused) void poll();
    return () => {
      stopped = true;
      generation++;
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [paused]);

  const numeric = (n: number | null | undefined, cpu = false) =>
    n === null || n === undefined || !Number.isFinite(n)
      ? '—'
      : cpu
        ? formatPercent(n, language, 1)
        : bytes(n, language);
  const usage = (kind: 'app' | 'core', value?: ProcessUsage) => (
    <article
      className={`resource-process resource-${kind}`}
      data-resource-process={kind}
      data-status={value?.status || 'waiting'}
    >
      <h3>
        <span className="resource-dot" />
        {t(kind)}
      </h3>
      <dl>
        <div>
          <dt>CPU</dt>
          <dd id={`resource-${kind}-cpu`}>{numeric(value?.cpuPercent, true)}</dd>
        </div>
        <div>
          <dt>RAM</dt>
          <dd id={`resource-${kind}-ram`}>
            {value?.status === 'partial' && value.rssBytes !== null ? `${t('approx')} ` : ''}
            {numeric(value?.rssBytes)}
          </dd>
        </div>
      </dl>
      <p className="field-hint" id={`resource-${kind}-status`}>
        {!value
          ? '—'
          : value.status === 'inactive'
            ? t('inactive')
            : value.status === 'unavailable'
              ? t('unavailable')
              : value.status === 'partial'
                ? t('partial')
                : `${translate(language, 'diagnostics.process_count', { count: value.processes })}${value.cpuPercent === null ? ` · ${t('baseline')}` : ''}`}
      </p>
    </article>
  );
  const ramMax = Math.max(1, ...history.flatMap((point) => [point.appRam || 0, point.coreRam || 0]));
  const ramKnown = history.some((point) => point.appRam !== null || point.coreRam !== null);
  const chart = (metric: 'Cpu' | 'Ram') => (
    <div className="resource-chart">
      <div>
        <span>{t(metric === 'Cpu' ? 'cpu' : 'ram')}</span>
        <span>{metric === 'Cpu' ? formatPercent(100, language) : numeric(ramKnown ? ramMax : null)}</span>
      </div>
      <svg
        viewBox="0 0 600 72"
        preserveAspectRatio="none"
        role="img"
        aria-label={`${t(metric === 'Cpu' ? 'cpu' : 'ram')} · ${t('minute')}`}
      >
        <path className="resource-chart-axis" d="M0,4 H600 M0,68 H600" />
        {(['app', 'core'] as const).flatMap((kind) =>
          resourcePaths(history, `${kind}${metric}`, metric === 'Cpu' ? 100 : ramMax).map((d, i) => (
            <path key={`${kind}-${i}`} className={`resource-line resource-${kind}`} d={d} />
          )),
        )}
      </svg>
    </div>
  );
  return (
    <section className="feature-panel desktop-section" id="process-resources" data-samples={history.length}>
      <div className="feature-panel-head resource-heading">
        <div>
          <h2>{t('title')}</h2>
          <p className="field-hint">{t('hint')}</p>
        </div>
        <Button
          id="resource-pause"
          className="text-button"
          aria-pressed={paused}
          onClick={() => setPaused(!paused)}
        >
          {t(paused ? 'resume' : 'pause')}
        </Button>
      </div>
      <p className="field-hint" id="resource-status">
        {paused
          ? t('paused')
          : failed
            ? t('unavailable')
            : snapshot?.supported === false
              ? t('unsupported')
              : t('live')}
      </p>
      {snapshot?.supported !== false && (
        <>
          <div className="resource-processes">
            {usage('app', snapshot?.app)}
            {usage('core', snapshot?.core)}
          </div>
          <div className="resource-charts">
            {chart('Cpu')}
            {chart('Ram')}
          </div>
          <p className="field-hint">{t('minute')}</p>
        </>
      )}
      <p className="field-hint resource-scope">{t('scope')}</p>
    </section>
  );
}

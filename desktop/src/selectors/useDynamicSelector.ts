import { errorCode } from '../shared/api/errors.ts';
import { useEffect, useRef, useState } from 'react';
import { command, type Draft, type Snapshot } from '../api';
import type { Config } from '../profiles/schema';
import { measureAndRank, type MeasurementProgress } from './measurements';
import { Preview } from './DynamicSelectorModel';
import type { Language } from '../shared/i18n/index.ts';
export function useDynamicSelector({
  libraryRevision = 0,
  config,
  groups,
  profiles,
  profileId,
  profileGroup,
  language,
  disabled,
  change,
  translateError,
}: {
  libraryRevision?: number;
  config: Config;
  groups: Snapshot['groups'];
  profiles: Snapshot['profiles'];
  profileId?: string;
  profileGroup: string;
  language: Language;
  disabled: boolean;
  change(c: Config): void;
  translateError(e: unknown): string;
}) {
  const source =
    config.member_source && typeof config.member_source === 'object' && !Array.isArray(config.member_source)
      ? (config.member_source as Config)
      : {};
  const usesHttp =
    source.order === 'http-latency' ||
    source.order === 'saved-http-latency' ||
    source.exclude_unavailable === true ||
    source.warm_start === true ||
    source.persist_health === true;
  const [reload, setReload] = useState(0);
  const [state, setState] = useState<{ key: string; result?: Preview; error?: string }>();
  const draft: Draft = {
    id: profileId,
    groupId: profileGroup,
    name: 'Pool preview',
    kind: 'auto-selector',
    config,
  };
  const draftText = JSON.stringify(draft);
  const candidates = JSON.stringify(profiles.map((p) => [p.id, p.name, p.kind, p.protocol, p.groupId]));
  const groupIds = JSON.stringify(groups.map((g) => g.id));
  const key = JSON.stringify([draftText, candidates, groupIds, libraryRevision, reload]);
  const latestDraft = useRef(draftText);
  latestDraft.current = draftText;
  const mounted = useRef(false);
  const [ranking, setRanking] = useState<{ key: string; busy?: boolean; error?: string }>();
  type Job = { draft: string; cancelled: boolean; batch?: string };
  const job = useRef<Job | undefined>(undefined);
  const [measurement, setMeasurement] = useState<{
    draft: string;
    busy?: boolean;
    progress?: MeasurementProgress;
    error?: string;
  }>();
  function cancelMeasurement(report: boolean) {
    const active = job.current;
    if (!active) return;
    active.cancelled = true;
    job.current = undefined;
    if (active.batch) void command('cancelUrlTestBatch', { id: active.batch }).catch(() => {});
    if (report) setMeasurement({ draft: active.draft, error: 'selector_measurements_cancelled' });
  }
  useEffect(() => () => cancelMeasurement(false), [draftText]);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  async function measure() {
    if (job.current) return;
    const active: Job = { draft: draftText, cancelled: false };
    job.current = active;
    const current = () =>
      mounted.current && job.current === active && !active.cancelled && latestDraft.current === active.draft;
    setMeasurement({ draft: active.draft, busy: true });
    try {
      const result = await measureAndRank(JSON.parse(active.draft), {
        command,
        current,
        progress: (progress) => {
          if (current()) setMeasurement({ draft: active.draft, busy: true, progress });
        },
        batch: (id) => {
          active.batch = id;
        },
      });
      if (current()) {
        job.current = undefined;
        setMeasurement(undefined);
        setSource('saved_ranking', result);
      }
    } catch (error) {
      if (current()) {
        job.current = undefined;
        setMeasurement({
          draft: active.draft,
          error: errorCode(error),
        });
      }
    }
  }
  // A ranking belongs to the draft it was asked for. Background library
  // changes (measurements, subscriptions) do not discard it; editing the
  // draft does.
  async function rank() {
    const requested = draftText;
    setRanking({ key: requested, busy: true });
    try {
      const result = await command('rankSelector', { profile: JSON.parse(requested) });
      if (mounted.current && latestDraft.current === requested) {
        setRanking({ key: requested });
        setSource('saved_ranking', result);
      }
    } catch (error) {
      if (mounted.current && latestDraft.current === requested)
        setRanking({ key: requested, error: errorCode(error) });
    }
  }

  useEffect(() => {
    let alive = true;
    const timer = setTimeout(() => {
      void command('previewSelector', { profile: JSON.parse(draftText) }).then(
        (result) => {
          if (alive) setState({ key, result });
        },
        (error) => {
          if (alive) setState({ key, error: errorCode(error) });
        },
      );
    }, 180);
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [key, draftText]);
  const current = state?.key === key ? state : undefined;
  const rankingState = ranking?.key === draftText ? ranking : undefined;
  const measurementState = measurement?.draft === draftText ? measurement : undefined;
  function setSource(field: string, value: unknown) {
    change({ ...config, member_source: { ...source, [field]: value } });
  }
  return {
    cancelMeasurement,
    change,
    config,
    current,
    disabled,
    groups,
    language,
    measure,
    measurementState,
    rank,
    rankingState,
    setReload,
    setSource,
    source,
    translateError,
    usesHttp,
  };
}

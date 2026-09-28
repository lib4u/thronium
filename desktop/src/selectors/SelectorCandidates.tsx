import { translate } from '../shared/i18n/index.ts';
import { formatMilliseconds } from '../shared/i18n/format.ts';
import type { useDynamicSelector } from './useDynamicSelector';
export default function SelectorCandidates({
  controller,
}: {
  controller: ReturnType<typeof useDynamicSelector>;
}) {
  const { current, language } = controller;

  if (!current?.result) return null;
  return (
    <div className="selector-candidates">
      {current.result.members.map((p) => (
        <div className="import-toggle" key={p.id} data-selector-preview-member={p.id}>
          <span>
            {p.name}
            {p.countryCode && <small>{p.countryCode}</small>}
            {p.httpSource === 'core-average' && (
              <small data-selector-core-average>
                {translate(language, 'library.core_http_average_804992a')}
              </small>
            )}
            {p.latencyMs !== undefined && (
              <small data-selector-http-latency>{formatMilliseconds(p.latencyMs, language)}</small>
            )}
            {p.httpTestFailed && (
              <small>{translate(language, 'library.last_http_check_failed_3081f2f')}</small>
            )}
          </span>
        </div>
      ))}
    </div>
  );
}

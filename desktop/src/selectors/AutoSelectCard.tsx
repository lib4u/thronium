import { Button } from '../shared/ui/controls';
import { Icon } from '../shared/ui/Icon';
import { plural, translate, type Language } from '../shared/i18n/index.ts';
import { autoSelectHint, autoSelectWords } from './autoSelectModel.ts';
import './AutoSelectCard.css';

export default function AutoSelectCard({
  language,
  selected,
  count,
  failover,
  disabled,
  onSelect,
  onConfigure,
}: {
  language: Language;
  selected: boolean;
  count: number;
  failover: boolean;
  disabled: boolean;
  onSelect(): void;
  onConfigure(): void;
}) {
  const t = (key: keyof typeof autoSelectWords) => translate(language, autoSelectWords[key]);
  return (
    <div className={`auto-select-card ${selected ? 'selected' : ''}`} id="auto-select-card">
      <Button
        type="button"
        className="auto-select-main"
        data-auto-select
        aria-pressed={selected}
        disabled={disabled}
        aria-describedby={disabled ? 'auto-select-unavailable' : undefined}
        onClick={onSelect}
      >
        <span className="auto-select-icon" aria-hidden="true">
          <Icon name="layers" />
        </span>
        <span className="auto-select-text">
          <span className="auto-select-heading">
            <strong>{t('title')}</strong>
            <span className="auto-select-badge">{t('recommended')}</span>
          </span>
          <small>{autoSelectHint(language, failover)}</small>
        </span>
        <span className="auto-select-indicator" aria-hidden="true" />
      </Button>
      <div className="auto-select-footer">
        <span className="auto-select-count">
          <Icon name="layers" />
          <span>
            {plural(language, 'library.auto_select_count', count)}
            {disabled && <small id="auto-select-unavailable">{t('unavailable')}</small>}
          </span>
        </span>
        <Button
          type="button"
          id="auto-select-configure"
          variant="text"
          title={t('configure')}
          aria-label={t('configure')}
          onClick={onConfigure}
        >
          <Icon name="sliders" />
          {t('configure')}
        </Button>
      </div>
    </div>
  );
}

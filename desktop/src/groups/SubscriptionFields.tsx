import { Section, Field } from '../shared/ui/controls';
import { Input, Checkbox, NumberField, Textarea } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import type * as Wire from '../shared/api/generated/commands';
import type { SubscriptionSettings } from '../api';
import NameRules from './NameRules';
import { tr, type Language } from './messages';
import { limits } from '../shared/api/generated/limits.ts';

// The headers editor holds JSON: quotes, separators and indentation add a few
// characters per header on top of the names and values the engine counts.
const headersTextLength = limits.maxSubscriptionHeaderBytes + limits.maxSubscriptionHeaders * 16;

/** Subscription source, schedule, request and naming settings of a group being edited. */
export default function SubscriptionFields({
  lang,
  subscription,
  showURL,
  setShowURL,
  patch,
  effectiveInterval,
  intervalText,
  setIntervalText,
  changeInterval,
  globalDefaults,
  headers,
  setHeaders,
}: {
  lang: Language;
  subscription: NonNullable<Wire.GroupDraft['subscription']>;
  showURL: boolean;
  setShowURL(value: boolean): void;
  patch(settings: Partial<SubscriptionSettings>): void;
  effectiveInterval?: number;
  intervalText?: string;
  setIntervalText(value?: string): void;
  changeInterval(text: string): void;
  globalDefaults?: { user_agent: string; sub_auto_update: number };
  headers: string;
  setHeaders(value: string): void;
}) {
  const t = (key: Parameters<typeof tr>[0]) => tr(key, lang);
  return (
    <>
      <Field className="feature-field" label={t('url')}>
        <Input
          id="group-url"
          className="text-input mono"
          type={showURL ? 'text' : 'password'}
          required
          maxLength={limits.maxSubscriptionUrlBytes}
          spellCheck={false}
          autoComplete="off"
          value={subscription.url}
          onChange={(e) => patch({ url: e.target.value })}
        />
      </Field>
      <label className="import-toggle">
        <Checkbox type="checkbox" checked={showURL} onChange={(e) => setShowURL(e.target.checked)} />
        {t('reveal')}
      </label>
      <p className="field-hint">{t('sourceHint')}</p>
      <label className="import-toggle">
        <Checkbox
          id="group-provider-routing"
          type="checkbox"
          checked={!!subscription.useProviderRouting}
          onChange={(e) => patch({ useProviderRouting: e.target.checked })}
        />
        {translate(lang, 'subscriptions.use_subscription_dns_and_routing_by_default_your_199a220')}
      </label>
      <label className="import-toggle">
        <Checkbox
          id="group-inherit-settings"
          type="checkbox"
          checked={subscription.inheritDefaults === true}
          onChange={(e) => patch({ inheritDefaults: e.target.checked })}
        />
        {translate(lang, 'subscriptions.use_global_user_agent_and_update_interval_da7c86a')}
      </label>
      <label className="import-toggle">
        <Checkbox
          id="group-auto-update"
          disabled={subscription.inheritDefaults === true}
          type="checkbox"
          checked={!!effectiveInterval}
          onChange={(e) => {
            setIntervalText(undefined);
            patch({ intervalMinutes: e.target.checked ? 60 : 0 });
          }}
        />
        {t('autoUpdate')}
      </label>
      {!!effectiveInterval && (
        <>
          <Field className="feature-field" label={t('interval')}>
            <NumberField
              id="group-update-interval"
              disabled={subscription.inheritDefaults === true}
              type="number"
              className="text-input"
              min={1}
              max={limits.maxSubscriptionIntervalMinutes}
              required
              value={
                subscription.inheritDefaults === true
                  ? effectiveInterval
                  : (intervalText ?? effectiveInterval)
              }
              onChange={(e) => changeInterval(e.target.value)}
            />
          </Field>
          <p className="field-hint">{t('scheduleHint')}</p>
        </>
      )}
      <Section title={<>{t('advanced')}</>} className="route-advanced">
        <Field className="feature-field" label={t('userAgent')}>
          <Input
            id="group-user-agent"
            disabled={subscription.inheritDefaults === true}
            className="text-input"
            maxLength={limits.maxSubscriptionUserAgentBytes}
            value={
              subscription.inheritDefaults === true
                ? globalDefaults?.user_agent || subscription.userAgent
                : subscription.userAgent
            }
            onChange={(e) => patch({ userAgent: e.target.value })}
          />
        </Field>
        <Field className="feature-field" label={t('headers')}>
          <Textarea
            id="group-headers"
            className="text-input mono"
            spellCheck={false}
            autoComplete="off"
            maxLength={headersTextLength}
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
          />
        </Field>
        <label className="import-toggle">
          <Checkbox
            id="group-via-proxy"
            type="checkbox"
            checked={subscription.viaProxy}
            onChange={(e) => patch({ viaProxy: e.target.checked })}
          />
          {t('viaProxy')}
        </label>
      </Section>
      <NameRules
        value={subscription.nameRules}
        language={lang}
        changed={(nameRules) => patch({ nameRules })}
      />
    </>
  );
}

import { Section, Field } from '../shared/ui/controls';
import { Button, Checkbox, Input, Textarea, Select } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { Icon } from '../ui';
import { groupName, isPersonalGroup } from '../groups/groupModel';
import { importProblem } from './ImportModel';
import type { useImportController } from './useImportController';
import { limits } from '../shared/api/generated/limits.ts';
export default function ImportSourceFields({
  controller,
}: {
  controller: ReturnType<typeof useImportController>;
}) {
  const {
    addSubscription,
    busy,
    dragging,
    filename,
    fileProblems,
    group,
    groups,
    language,
    method,
    name,
    paste,
    read,
    scan,
    setDragging,
    setGroup,
    setName,
    setSource,
    subscription,
    subscriptionAutoUpdate,
    setSubscriptionAutoUpdate,
    subscriptionTitle,
    text,
    tr,
  } = controller;
  const target = groups.find((g) => g.id === group) ?? groups.find((g) => isPersonalGroup(g.id));
  const groupTitle = target ? groupName(target, language) : '';

  return (
    <div id="import-method-panel" role="tabpanel" aria-labelledby={`import-tab-${method}`}>
      <Field
        className="feature-field"
        label={
          <>
            {tr('name')} <small>{translate(language, 'profiles.optional_cb3cd23')}</small>
          </>
        }
      >
        <Input
          id="import-title"
          className="text-input"
          maxLength={limits.maxNameBytes}
          placeholder={translate(language, 'profiles.for_example_my_subscription_877649c')}
          disabled={busy}
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
      </Field>
      {method === 'link' ? (
        <>
          <Field className="feature-field" label={translate(language, 'profiles.connection_link_2c6cc3e')}>
            <Textarea
              id="import-source"
              className="text-input mono import-source"
              placeholder="https://, vless://, ss://, tt://, throne://…"
              autoComplete="off"
              spellCheck={false}
              disabled={busy}
              value={text}
              onChange={(e) => setSource(e.target.value)}
            />
          </Field>
          <div className="import-source-actions">
            <p className="field-hint">
              {translate(language, 'profiles.subscription_profile_links_or_configuration_text_2eae89a')}
            </p>
            <Button
              className="text-button"
              id="import-clipboard"
              disabled={busy}
              onClick={() => void paste()}
            >
              <Icon name="copy" />
              {tr('clipboard')}
            </Button>
          </div>
        </>
      ) : (
        <>
          <div
            className={`import-dropzone ${dragging ? 'is-dragging' : ''}`}
            onDragOver={(e) => {
              e.preventDefault();
              if (!busy) setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              void read(e.dataTransfer.files);
            }}
          >
            <Icon name={method === 'qr' ? 'qr' : 'file-plus'} />
            <strong>
              {filename ||
                (method === 'qr'
                  ? translate(language, 'profiles.choose_a_qr_image_1ab6946')
                  : translate(language, 'profiles.choose_a_configuration_file_a0c7e53'))}
            </strong>
            <small>
              {method === 'qr' ? 'PNG, JPG, WEBP, GIF, BMP' : 'JSON, YAML, CONF, TXT, INI, OVPN, XML'}
            </small>
            <label className="button secondary import-file-button">
              {tr('file')}
              <Input
                id="import-file"
                className="sr-only"
                type="file"
                multiple
                disabled={busy}
                accept={method === 'qr' ? 'image/png,image/jpeg,image/webp,image/gif,image/bmp' : undefined}
                onChange={(e) => {
                  void read(e.target.files);
                  e.target.value = '';
                }}
              />
            </label>
            <small>{translate(language, 'profiles.or_drag_files_here_db124c6')}</small>
          </div>
          {method === 'qr' && (
            <div className="import-qr-actions">
              <Button
                id="import-qr-clipboard"
                className="button secondary"
                disabled={busy}
                onClick={() => void scan('readQrClipboard')}
              >
                <Icon name="copy" />
                {translate(language, 'profiles.from_clipboard_143cdfa')}
              </Button>
              <Button
                id="import-qr-screen"
                className="button secondary"
                disabled={busy}
                onClick={() => void scan('scanScreenQr')}
              >
                <Icon name="laptop" />
                {translate(language, 'profiles.scan_screen_b97cd2a')}
              </Button>
            </div>
          )}
          {method === 'file' && fileProblems.length > 0 && (
            <ul className="import-file-problems" id="import-file-problems" role="alert">
              {fileProblems.map((problem) => (
                <li
                  key={problem.filename}
                >{`${problem.filename}: ${importProblem(problem.code, language)}`}</li>
              ))}
            </ul>
          )}
          {text && (
            <p className="import-read-success" role="status">
              <Icon name="check-circle" />
              {translate(language, 'profiles.content_loaded_continue_to_review_79cb34c')}
            </p>
          )}
        </>
      )}
      {subscription?.link && (
        <dl className="import-subscription-source">
          <dt>{tr('name')}</dt>
          <dd id="import-subscription-name">{subscriptionTitle()}</dd>
          <dt>{translate(language, 'subscriptions.subscription_url_dc7ed9c')}</dt>
          <dd id="import-subscription-url">{subscription.url}</dd>
        </dl>
      )}
      {subscription && (
        <label className="import-toggle">
          <Checkbox
            id="import-subscription-auto-update"
            type="checkbox"
            disabled={busy}
            checked={subscriptionAutoUpdate}
            onChange={(e) => setSubscriptionAutoUpdate(e.target.checked)}
          />
          {translate(language, 'subscriptions.update_automatically_229b23c')}
        </label>
      )}
      {subscription && (
        <p className="field-hint">
          {translate(language, 'profiles.a_separate_group_will_be_created_its_servers_wil_7f55258')}
          {!subscription.automatic && (
            <>
              {' '}
              <Button
                id="import-as-subscription"
                className="text-button"
                disabled={busy}
                onClick={() => void addSubscription()}
              >
                {tr('addSubscription')}
              </Button>
            </>
          )}
        </p>
      )}
      {!subscription?.automatic && (
        <Section
          title={
            <>
              {tr('group')}: {groupTitle}
            </>
          }
          className="import-destination"
        >
          <Field className="feature-field" label={tr('group')}>
            <Select
              id="import-group"
              className="text-input"
              value={group}
              disabled={busy}
              onChange={(e) => setGroup(e.target.value)}
            >
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {groupName(g, language)}
                </option>
              ))}
            </Select>
          </Field>
        </Section>
      )}
    </div>
  );
}

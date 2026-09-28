import ProfileField from './ProfileField';
import { formatJson, TabList, Field as FormField } from '../shared/ui/controls';
import { InlineError, JsonEditor, Notice } from '../shared/ui/controls';
import { Select, Input, Button } from '../shared/ui/controls';
import { messageRef } from '../shared/i18n/message';
import { translate } from '../shared/i18n/index.ts';
import { type VlessCore } from '../api';
import WarpGenerator from '../warp/Generator';
import { profileDraft } from '../warp/config';
import { Modal, Icon } from '../ui';
import ChainFields from './ChainFields';
import VpnPolicyFields from './VpnPolicyFields';
import ExternalCoreFields from './ExternalCoreFields';
import SelectorFields from '../selectors/Fields';
import { groupName } from '../groups/groupModel';
import WsEarlyDataField from './WsEarlyDataField';
import { wsBuffer } from './wsEarlyData';
import { definitions, get, label, peerFields, type Field } from './schema';
import type { useProfileEditor } from './useProfileEditor';
import { limits } from '../shared/api/generated/limits.ts';
import { allTraffic, WIREGUARD_PORT } from './wireguardDefaults';
export default function ProfileForm({ controller }: { controller: ReturnType<typeof useProfileEditor> }) {
  const {
    Frame,
    active,
    busy,
    changeEarlyData,
    changeVpnPolicy,
    chooseExternalCore,
    chooseTab,
    confirmClose,
    conflict,
    current,
    def,
    disconnect,
    draft,
    earlyPath,
    earlyTransport,
    editPeers,
    error,
    generateKey,
    groupId,
    groups,
    importFile,
    inUse,
    isVless,
    language,
    libraryRevision,
    name,
    parsed,
    peers,
    profiles,
    publicKey,
    raw,
    changeConfig,
    removeCustomFragment,
    setConfirmKey,
    setConfirmReload,
    setDirty,
    setError,
    setGroup,
    setName,
    setPublicKey,
    setStatus,
    setVlessCore,
    status,
    submit,
    supportsVpnPolicy,
    tailscaleNode,
    switchType,
    t,
    tabs,
    tr,
    translateError,
    type,
    update,
    vlessCore,
    vpnPolicy,
  } = controller;
  function renderField(field: Field) {
    return <ProfileField key={field.path} field={field} controller={controller} />;
  }
  return (
    <form
      id="profile-editor"
      onSubmit={(e) => {
        e.preventDefault();
        void submit(false);
      }}
      inert={confirmClose || undefined}
    >
      <div className="editor-type">
        <FormField className="feature-field" label={t('protocol')}>
          <Select
            className="text-input"
            id="profile-type"
            value={type}
            disabled={busy}
            onChange={(e) => switchType(e.target.value)}
          >
            {definitions.map((d) => (
              <option value={d.id} key={d.id}>
                {label(d.label, language)}
              </option>
            ))}
          </Select>
        </FormField>
        <FormField className="feature-field" label={t('group')}>
          <Select
            className="text-input"
            id="profile-group"
            value={groupId}
            onChange={(e) => {
              setGroup(e.target.value);
              setDirty(true);
            }}
            disabled={busy}
          >
            {groups.map((g) => (
              <option key={g.id} value={g.id}>
                {groupName(g, language)}
              </option>
            ))}
          </Select>
        </FormField>
      </div>

      {vpnPolicy && !supportsVpnPolicy && (
        <div className="feature-section" id="vpn-policy-unsupported">
          <InlineError className="field-error" role="alert">
            {translate(language, 'profiles.this_protocol_does_not_support_the_vpn_routing_a_66216ff')}
          </InlineError>
          <Button
            type="button"
            id="vpn-policy-clear-unsupported"
            className="text-button"
            disabled={busy}
            onClick={() => changeVpnPolicy(null)}
          >
            {translate(language, 'profiles.remove_vpn_policy_54abd54')}
          </Button>
        </div>
      )}

      <div className="editor-layout">
        <TabList
          className="editor-nav"
          aria-label={tr('fields')}
          aria-orientation="vertical"
          value={active.id}
          onChange={chooseTab}
          tabs={tabs.map((s) => ({
            id: s.id,
            attributes: { 'data-profile-tab': s.id },
            label: (
              <>
                {label(s.label, language)}
                {(s.fields.some((f) => current.invalid[f.path]) ||
                  (s.id === 'transport' && current.invalid[wsBuffer])) && (
                  <span className="editor-invalid-dot" />
                )}
              </>
            ),
          }))}
        />
        <div className="editor-content" id="profile-content">
          {active.id === 'main' ? (
            <div className="feature-section">
              <div className="editor-section-heading">
                <h3>{label(def.label, language)}</h3>
                {isVless && (
                  <FormField
                    className="feature-field"
                    label={translate(language, 'profiles.vless_core_d336ca0')}
                  >
                    <Select
                      id="editor-vless-core"
                      className="text-input"
                      value={vlessCore}
                      disabled={busy}
                      onChange={(e) => {
                        setVlessCore(e.target.value as VlessCore | 'default');
                        setDirty(true);
                        setStatus('');
                      }}
                    >
                      <option value="default">{translate(language, 'profiles.default_de0b656')}</option>
                      <option value="xray">Xray</option>
                      <option value="sing-box">sing-box</option>
                    </Select>
                  </FormField>
                )}
                {!isVless && (
                  <span className="editor-core-label">
                    {def.kind.startsWith('xray')
                      ? 'Xray'
                      : def.kind === 'chain'
                        ? 'sing-box / Xray'
                        : def.kind === 'external-core'
                          ? label(def.label, language)
                          : 'sing-box'}
                  </span>
                )}
              </div>
              <FormField className="feature-field" label={t('name')}>
                <Input
                  autoFocus={Frame === Modal}
                  id="profile-name"
                  className="text-input"
                  value={name}
                  onChange={(e) => {
                    setName(e.target.value);
                    setDirty(true);
                  }}
                  maxLength={limits.maxNameBytes}
                  disabled={busy}
                />
              </FormField>
            </div>
          ) : (
            <div className="feature-section">
              <h3>{label(active.label, language)}</h3>
            </div>
          )}
          {active.id === 'vpn-policy' ? (
            <VpnPolicyFields
              value={vpnPolicy ?? null}
              language={language}
              disabled={busy || !parsed}
              node={tailscaleNode}
              change={changeVpnPolicy}
            />
          ) : active.id === 'json' ? (
            <>
              <p className="field-hint">{tr(def.kind === 'external-core' ? 'externalRawHint' : 'rawHint')}</p>
              <JsonEditor
                id="profile-json"
                aria-label={t('configuration')}
                className="text-input mono desktop-json"
                spellCheck={false}
                autoComplete="off"
                value={current.text}
                onChange={(e) => raw(e.target.value)}
                disabled={busy}
              />
              <Button
                type="button"
                className="text-button desktop-section"
                onClick={() => {
                  if (parsed) raw(formatJson(current.text));
                  else setError(messageRef('common.jsonInvalid'));
                }}
              >
                {tr('formatJson')}
              </Button>
            </>
          ) : (
            <>
              {!parsed && (
                <InlineError className="field-error" role="alert">
                  {t('jsonInvalid')}
                </InlineError>
              )}
              {type.startsWith('custom') && <p className="field-hint">{tr('rawOnly')}</p>}
              <div className="feature-fields">
                {active.fields.map(renderField)}
                {active.id === 'transport' && earlyTransport && (
                  <WsEarlyDataField
                    transport={earlyTransport}
                    path={get(parsed, earlyPath)}
                    buffer={current.buffers[wsBuffer]}
                    invalid={current.invalid[wsBuffer]}
                    disabled={busy || !parsed}
                    language={language}
                    change={changeEarlyData}
                  />
                )}
              </div>
              {type === 'chain' && active.id === 'main' && (
                <ChainFields
                  config={parsed || {}}
                  profiles={profiles}
                  selfId={draft?.id}
                  language={language}
                  disabled={busy || !parsed}
                  change={changeConfig}
                />
              )}
              {active.fields.some((field) => field.path === 'tls_fragment.enabled') && (
                <div className="desktop-section" id="custom-fragment-actions">
                  {get(parsed, 'tls_fragment.enabled') === true && get(parsed, 'tcp_fast_open') === true && (
                    <p className="field-error" id="custom-fragment-tfo" role="status">
                      {tr('customFragmentTfo')}
                    </p>
                  )}
                  <Button
                    type="button"
                    className="text-button"
                    id="custom-fragment-remove"
                    disabled={busy || !parsed || get(parsed, 'tls_fragment') === undefined}
                    onClick={removeCustomFragment}
                  >
                    {tr('customFragmentReset')}
                  </Button>
                  <p className="field-hint">{tr('customFragmentResetHint')}</p>
                </div>
              )}
              {type === 'extracore' && active.id === 'main' && (
                <ExternalCoreFields
                  config={parsed || {}}
                  language={language}
                  disabled={busy || !parsed}
                  change={changeConfig}
                  choose={() => void chooseExternalCore()}
                />
              )}
              {type === 'autoselector' && active.id === 'main' && (
                <SelectorFields
                  libraryRevision={libraryRevision}
                  config={parsed || {}}
                  profiles={profiles}
                  groups={groups}
                  profileId={draft?.id}
                  profileGroup={groupId}
                  translateError={translateError}
                  language={language}
                  disabled={busy || !parsed}
                  change={changeConfig}
                />
              )}
              {active.id === 'main' && ['wireguard', 'amneziawg'].includes(type) && (
                <div className="editor-keygen">
                  <Button
                    type="button"
                    className="button secondary"
                    disabled={busy || !parsed}
                    onClick={() => (get(parsed, 'private_key') ? setConfirmKey(true) : void generateKey())}
                  >
                    {tr('generate')}
                  </Button>
                  {publicKey && (
                    <FormField className="feature-field desktop-section" label={tr('publicKey')}>
                      <Input
                        className="text-input mono"
                        aria-label={tr('publicKey')}
                        readOnly
                        value={publicKey}
                      />
                      <small className="field-hint">{tr('generated')}</small>
                    </FormField>
                  )}
                </div>
              )}
              {active.id === 'peers' && (
                <>
                  {type === 'wireguard' && (
                    <WarpGenerator
                      language={language}
                      disabled={busy || !parsed}
                      translateError={translateError}
                      profile
                      useConfig={(config) => {
                        update(profileDraft(current, config));
                        setPublicKey(config.clientPublicKey);
                      }}
                    />
                  )}
                  {!peers.length && <p className="field-hint">{tr('noPeers')}</p>}
                  {peers.map((_, i) => (
                    <section className="editor-card" key={i}>
                      <div className="feature-panel-head">
                        <h3>
                          {tr('peer')} {i + 1}
                        </h3>
                        <Button
                          type="button"
                          className="text-button"
                          disabled={busy}
                          onClick={() =>
                            editPeers(
                              peers.filter((_, index) => i !== index),
                              i,
                            )
                          }
                        >
                          {t('remove')}
                        </Button>
                      </div>
                      <div className="feature-fields">
                        {peerFields.map((field) =>
                          renderField({ ...field, path: `peers.${i}.${field.path}` }),
                        )}
                      </div>
                    </section>
                  ))}
                  <Button
                    type="button"
                    className="button secondary"
                    disabled={busy || !parsed}
                    onClick={() =>
                      editPeers([
                        ...peers,
                        { address: '', port: WIREGUARD_PORT, public_key: '', allowed_ips: allTraffic() },
                      ])
                    }
                  >
                    <Icon name="plus" />
                    {tr('addPeer')}
                  </Button>
                </>
              )}
            </>
          )}
        </div>
      </div>
      <div className="editor-import">
        <label className="button secondary desktop-file">
          <Icon name="upload" />
          {t('importFile')}
          <Input
            className=""
            type="file"
            accept=".json,application/json"
            disabled={busy}
            onChange={(e) => {
              void importFile(e.target.files?.[0]);
              e.target.value = '';
            }}
          />
        </label>
        <small className="field-hint">{tr('unknown')}</small>
      </div>
      {inUse && (
        <div className="editor-running-note" id="editor-running-note">
          <p>{translate(language, 'profiles.this_profile_is_in_use_disconnect_to_save_change_9930e05')}</p>
          <Button
            id="editor-disconnect"
            type="button"
            className="button secondary"
            disabled={busy}
            onClick={() => void disconnect()}
          >
            {t('disconnect')}
          </Button>
        </div>
      )}
      {conflict && (
        <Button
          id="profile-reload"
          type="button"
          className="button secondary"
          disabled={busy}
          onClick={() => setConfirmReload(true)}
        >
          {t('profileReload')}
        </Button>
      )}
      {error && (
        <InlineError className="field-error" role="alert">
          {error}
        </InlineError>
      )}
      {status && (
        <Notice kind="success" className="desktop-success" role="status">
          {status}
        </Notice>
      )}
    </form>
  );
}

import { Button, InlineError } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { command } from '../api';
import AutoSelectConfig from '../selectors/AutoSelectConfig';
import VpnAuthDialog from '../connection/VpnAuthDialog';
import VpnCredentialsDialog from '../connection/VpnCredentialsDialog';
import { credentialsKey } from '../connection/vpnCredentials';
import VpnOtpBindingDialog from '../connection/VpnOtpBindingDialog';
import { challengeKey, vpnEndpointLabel } from '../connection/vpnAuth';
import OtpQuickDialog from '../otp/QuickDialog';
import { Modal, Icon } from '../ui';
import DropdownMenu, { type MenuItem } from '../DropdownMenu';
import Editor from '../profiles/Editor';
import AddDialog from '../profiles/AddDialog';
import BatchDialog from '../profiles/BatchDialog';
import ExportDialog, { exportText } from '../profiles/ExportDialog';
import ConfigurationDialog from '../profiles/ConfigurationDialog';
import DuplicatesDialog from '../library/DuplicatesDialog';
import MaintenanceDialog from '../library/MaintenanceDialog';
import { orderNeighbor, orderText } from '../library/profileOrder';
import TestActions from '../settings/TestActions';
import GroupsDialog from '../groups/GroupsDialog';
import { GroupMenu } from '../groups/LibraryGroups';
import UpdatesDialog from '../groups/UpdatesDialog';
import SubscriptionDialog from '../groups/SubscriptionDialog';
import type { useAppController } from '../useAppController';
import { profilesOf } from '../groups/groupModel';
export default function DialogHost({ controller }: { controller: ReturnType<typeof useAppController> }) {
  const {
    busy,
    error,
    modal,
    perform,
    refresh,
    setModal,
    state,
    subscriptionGroup,
    t,
    toast,
    setToast,
    translateError,
    profiles: { clone, configure, edit },
    connection: { current, vpn },
    menus: { menu, menuGroup, menuProfile, setMenu },
    library: { moveNeighbor, orderReason, resetFilters, setGroup, setSelection },
    probes: { probeAction, probesBlocked },
  } = controller;
  return (
    <>
      {menu?.type === 'group' && menuGroup && (
        <GroupMenu
          snapshot={state}
          group={menuGroup}
          busy={busy}
          probeBusy={probesBlocked}
          anchor={menu.anchor}
          edge={menu.edge}
          close={() => setMenu(null)}
          edit={() => setModal({ type: 'groups', initialGroupId: menuGroup.id, initialAction: 'edit' })}
          remove={() => setModal({ type: 'groups', initialGroupId: menuGroup.id, initialAction: 'delete' })}
          move={(offset) => void perform(() => command('moveGroup', { id: menuGroup.id, offset }))}
          update={() => void perform(() => command('startSubscriptionUpdates', { id: menuGroup.id }))}
          probe={() =>
            void probeAction(
              'startPing',
              profilesOf(state.profiles, menuGroup.id).map((p) => p.id),
            )
          }
          review={() => setModal({ type: 'subscription', groupId: menuGroup.id })}
        />
      )}
      {menu?.type === 'profile' && menuProfile && (
        <DropdownMenu
          anchor={menu.anchor}
          edge={menu.edge}
          label={`${t('parameters')}: ${menuProfile.name}`}
          close={() => setMenu(null)}
          items={[
            {
              id: 'diagnostics-one',
              label: translate(state.preferences.language, 'common.ip_country_and_speed_6c5c817'),
              icon: 'activity',
              select: () => setModal({ type: 'diagnostics', profileId: menuProfile.id }),
            },
            {
              id: 'probe-one',
              label: translate(state.preferences.language, 'common.test_latency_665c69a'),
              icon: 'activity',
              disabled: probesBlocked,
              select: () => void probeAction('startPing', [menuProfile.id]),
            },
            { id: 'menu-edit-profile', label: t('edit'), icon: 'edit', select: () => void edit(menuProfile) },
            ...(menuProfile.kind === 'sing-box-outbound' && menuProfile.vpn
              ? [
                  {
                    id: 'menu-vpn-otp-profile',
                    label: translate(state.preferences.language, 'common.automatic_otp_code_c536745'),
                    icon: 'lock',
                    select: () => setModal({ type: 'vpn-otp', profile: menuProfile }),
                  } satisfies MenuItem,
                ]
              : []),
            {
              id: 'menu-clone-profile',
              label: t('clone'),
              icon: 'copy',
              select: () => void clone(menuProfile),
            },
            {
              id: 'profile-move-up',
              label: orderText('up', state.preferences.language),
              icon: 'arrow-up',
              separator: true,
              disabled: !!orderReason || !orderNeighbor(state.profiles, menuProfile.id, -1),
              select: () => moveNeighbor(menuProfile.id, -1),
            },
            {
              id: 'profile-move-down',
              label: orderText('down', state.preferences.language),
              icon: 'arrow-down',
              disabled: !!orderReason || !orderNeighbor(state.profiles, menuProfile.id, 1),
              select: () => moveNeighbor(menuProfile.id, 1),
            },
            {
              id: 'export-one',
              label: ['chain', 'auto-selector'].includes(menuProfile.kind)
                ? exportText('title', state.preferences.language)
                : translate(state.preferences.language, 'common.export_and_edit_509118e'),
              icon: 'file',
              select: () =>
                ['chain', 'auto-selector'].includes(menuProfile.kind)
                  ? setModal({ type: 'export', ids: [menuProfile.id] })
                  : void configure(menuProfile),
            },
            {
              id: 'menu-delete-profile',
              label: t('remove'),
              icon: 'trash',
              danger: true,
              separator: true,
              select: () =>
                state.appearance?.skip_delete_confirmation
                  ? void perform(() => command('deleteProfiles', { ids: [menuProfile.id] }))
                  : setModal({ type: 'delete', profile: menuProfile }),
            },
          ]}
        />
      )}
      {modal?.type === 'auto-select-config' && (
        <AutoSelectConfig
          snapshot={state}
          close={() => setModal(null)}
          refresh={refresh}
          translateError={translateError}
        />
      )}
      {modal?.type === 'vpn-otp' && (
        <VpnOtpBindingDialog
          key={modal.profile.id}
          profile={modal.profile}
          language={state.preferences.language}
          close={() => setModal(null)}
          changed={refresh}
        />
      )}
      {modal?.type === 'vpn-credentials' && (
        <VpnCredentialsDialog
          key={credentialsKey(modal.request)}
          request={modal.request}
          label={vpnEndpointLabel(modal.request.endpointTag, current)}
          status={vpn}
          language={state.preferences.language}
          close={() => setModal(null)}
          refresh={refresh}
        />
      )}
      {modal?.type === 'vpn-auth' && (
        <VpnAuthDialog
          key={challengeKey(modal.request)}
          request={modal.request}
          label={vpnEndpointLabel(modal.request.endpointTag, current)}
          status={vpn}
          language={state.preferences.language}
          close={() => setModal(null)}
          refresh={refresh}
        />
      )}
      {modal?.type === 'otp-quick' && (
        <OtpQuickDialog
          language={state.preferences.language}
          close={() => setModal(null)}
          translateError={translateError}
        />
      )}
      {modal?.type === 'diagnostics' && (
        <Modal
          title={translate(state.preferences.language, 'common.server_diagnostics_fddb384')}
          close={() => setModal(null)}
        >
          <TestActions
            snapshot={state}
            profileId={modal.profileId}
            internet={false}
            translateError={translateError}
          />
        </Modal>
      )}
      {modal?.type === 'configuration' && (
        <ConfigurationDialog
          preferences={state.preferences}
          draft={modal.draft}
          language={state.preferences.language}
          runningId={state.running}
          close={() => setModal(null)}
          changed={refresh}
          translateError={translateError}
        />
      )}
      {modal?.type === 'export' && (
        <ExportDialog
          snapshot={state}
          ids={modal.ids}
          close={() => setModal(null)}
          translateError={translateError}
        />
      )}
      {modal?.type === 'batch' && (
        <BatchDialog
          snapshot={state}
          ids={modal.ids}
          operation={modal.operation}
          close={() => setModal(null)}
          changed={refresh}
          completed={(target) => {
            setSelection(new Set());
            if (target) {
              setGroup(target);
              resetFilters();
            }
          }}
          translateError={translateError}
        />
      )}
      {modal?.type === 'add' && (
        <AddDialog
          snapshot={state}
          initialGroup={modal.initialGroup}
          initialText={modal.initialText}
          initialDocuments={modal.initialDocuments}
          initialProblems={modal.initialProblems}
          subscribe={(id) => {
            setGroup(id);
            resetFilters();
            setModal(null);
          }}
          close={() => setModal(null)}
          changed={refresh}
          t={t}
          translateError={translateError}
        />
      )}
      {modal?.type === 'duplicates' && (
        <DuplicatesDialog
          snapshot={state}
          ids={modal.ids}
          close={() => setModal(null)}
          changed={refresh}
          translateError={translateError}
        />
      )}
      {modal?.type === 'maintenance' && (
        <MaintenanceDialog
          snapshot={state}
          kind={modal.kind}
          ids={modal.ids}
          close={() => setModal(null)}
          changed={refresh}
          notify={setToast}
          translateError={translateError}
        />
      )}
      {modal?.type === 'editor' && (
        <Editor
          libraryRevision={state.libraryRevision}
          initialGroup={modal.initialGroup}
          key={modal.draft?.id || 'new'}
          draft={modal.draft}
          runningId={state.running}
          groups={state.groups}
          profiles={state.profiles}
          language={state.preferences.language}
          t={t}
          translateError={translateError}
          close={() => setModal(null)}
          changed={refresh}
        />
      )}
      {modal?.type === 'delete' && (
        <Modal
          title={t('deleteTitle')}
          description={t('deleteHint')}
          close={() => setModal(null)}
          footer={
            <>
              <Button className="text-button" onClick={() => setModal(null)}>
                {t('cancel')}
              </Button>
              <Button
                className="button primary"
                disabled={busy}
                onClick={() =>
                  void perform(
                    () => command('deleteProfiles', { ids: [modal.profile.id] }),
                    () => setModal(null),
                  )
                }
              >
                {t('deleteConfirm')}
              </Button>
            </>
          }
        >
          <p>{modal.profile.name}</p>
          {/* The shared banner sits behind the dialog; a refusal is shown where the user acts. */}
          {error && (
            <InlineError className="desktop-inline-error" role="alert">
              {translateError(error)}
            </InlineError>
          )}
        </Modal>
      )}
      {modal?.type === 'updates' && (
        <UpdatesDialog
          snapshot={state}
          close={() => setModal(null)}
          changed={refresh}
          review={(groupId) => setModal({ type: 'subscription', groupId })}
          translateError={translateError}
        />
      )}
      {modal?.type === 'groups' && (
        <GroupsDialog
          initialGroupId={modal.initialGroupId}
          initialAction={modal.initialAction}
          updates={() => setModal({ type: 'updates' })}
          snapshot={state}
          close={() => setModal(null)}
          changed={refresh}
          update={(groupId) => setModal({ type: 'subscription', groupId })}
          translateError={translateError}
        />
      )}
      {modal?.type === 'subscription' && subscriptionGroup && (
        <SubscriptionDialog
          autoLoad={modal.autoLoad}
          key={subscriptionGroup.id}
          group={subscriptionGroup}
          language={state.preferences.language}
          close={() => setModal(null)}
          changed={refresh}
          translateError={translateError}
        />
      )}
      {toast && (
        <div className="toast-stack" role="status">
          <div className="toast">
            <Icon name="check-circle" />
            <span>{toast}</span>
          </div>
        </div>
      )}
    </>
  );
}

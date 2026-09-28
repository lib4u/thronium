import { Button } from '../shared/ui/controls';
import { translate } from '../shared/i18n/index.ts';
import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import type { Snapshot } from '../api';
import type { Key } from '../i18n';
import { ConfirmDialog, Icon, Modal } from '../ui';
import Editor from './Editor';
import ImportDialog, { type ImportMethod } from './ImportDialog';
import { PaneContext, PaneFrame } from './DialogPane';
import './AddDialog.css';
import './ImportFlow.css';
import { personalGroupId } from '../groups/groupModel';

type Mode = 'choice' | 'import' | 'advanced';
export default function AddDialog({
  snapshot,
  initialGroup,
  initialText,
  initialDocuments,
  initialProblems,
  close,
  changed,
  subscribe,
  t,
  translateError,
}: {
  snapshot: Snapshot;
  initialGroup?: string;
  initialText?: string;
  initialDocuments?: { filename: string; text: string }[];
  initialProblems?: { filename: string; code: string }[];
  close(): void;
  changed(): Promise<void>;
  subscribe(groupId: string): void;
  t(k: Key): string;
  translateError(e: unknown): string;
}) {
  const language = snapshot.preferences.language;
  const received = initialDocuments || initialProblems;
  const [mode, setMode] = useState<Mode>(initialText || received ? 'import' : 'choice');
  const [visited, setVisited] = useState(false);
  const [method, setMethod] = useState<ImportMethod>(received ? 'file' : 'link');
  const [review, setReview] = useState(false);
  const [group, setGroup] = useState(initialGroup && initialGroup !== 'all' ? initialGroup : personalGroupId);
  const [footer, setFooter] = useState<HTMLDivElement | null>(null);
  const [quickBusy, setQuickBusy] = useState(false);
  const [advanced, setAdvanced] = useState({ busy: false, dirty: false });
  const [confirmClose, setConfirmClose] = useState(false);
  const focus = useRef<HTMLElement | null>(null);
  const quickActivity = useCallback((busy: boolean) => setQuickBusy(busy), []);
  const advancedActivity = useCallback(
    (busy: boolean, dirty: boolean) =>
      setAdvanced((old) => (old.busy === busy && old.dirty === dirty ? old : { busy, dirty })),
    [],
  );
  const busy = quickBusy || advanced.busy;
  useLayoutEffect(() => {
    const id = requestAnimationFrame(() =>
      document
        .querySelector<HTMLElement>(
          mode === 'choice' ? '#add-choice-link' : mode === 'advanced' ? '#profile-name' : '#import-title',
        )
        ?.focus({ preventScroll: true }),
    );
    return () => cancelAnimationFrame(id);
  }, [mode]);
  const requestClose = () => {
    if (busy || confirmClose) return;
    if (advanced.dirty) {
      focus.current = document.activeElement as HTMLElement;
      setConfirmClose(true);
    } else close();
  };
  function choose(next: ImportMethod | 'advanced') {
    if (busy) return;
    if (next === 'advanced') {
      setVisited(true);
      setMode('advanced');
    } else {
      setMethod(next);
      setMode('import');
    }
  }
  const choices = [
    [
      'link',
      'link',
      translate(language, 'profiles.link_or_clipboard_a2f8884'),
      translate(language, 'profiles.subscription_profile_uri_throne_vpn_e6d2371'),
    ],
    [
      'file',
      'file',
      translate(language, 'profiles.configuration_file_6563273'),
      'JSON, YAML, CONF, INI, OVPN, XML',
    ],
    [
      'qr',
      'qr',
      translate(language, 'profiles.qr_code_f15bdf0'),
      translate(language, 'profiles.image_clipboard_or_screen_capture_7621e68'),
    ],
    [
      'advanced',
      'sliders',
      translate(language, 'profiles.enter_manually_4553486'),
      translate(language, 'profiles.protocol_transport_and_connection_parameters_84a7997'),
    ],
  ] as const;
  return (
    <Modal
      title={
        mode === 'choice'
          ? translate(language, 'profiles.add_connection_eb70f68')
          : mode === 'advanced'
            ? translate(language, 'profiles.new_profile_9f722c5')
            : translate(language, 'profiles.new_connection_0f49bbd')
      }
      description={
        mode === 'choice'
          ? translate(language, 'profiles.subscription_ready_configuration_or_your_own_par_7a0ed07')
          : mode === 'advanced'
            ? translate(language, 'profiles.protocol_and_connection_parameters_88fe0f5')
            : translate(language, 'profiles.one_profile_or_a_subscription_with_multiple_serv_ece488a')
      }
      className={`connection-add-modal compact-profile-modal import-flow ${mode === 'advanced' ? 'editor-modal add-manual' : mode === 'import' && review ? 'add-review' : 'add-compact'} ${mode === 'choice' ? 'add-chooser' : ''}`}
      navigation={
        mode !== 'choice' ? (
          <div className="add-back">
            <Button className="text-button" disabled={busy} onClick={() => setMode('choice')}>
              <Icon name="arrow-left" />
              {translate(language, 'profiles.all_ways_to_add_1141434')}
            </Button>
          </div>
        ) : undefined
      }
      footer={mode === 'choice' ? undefined : <></>}
      footerRef={setFooter}
      inert={confirmClose}
      close={requestClose}
      closeLabel={t('close')}
      initialFocus="#add-choice-link"
    >
      <div className="connection-add-panels" aria-busy={busy}>
        {mode === 'choice' && (
          <div className="add-methods">
            {choices.map(([value, icon, title, hint]) => (
              <Button
                className=""
                type="button"
                id={`add-choice-${value}`}
                key={value}
                onClick={() => choose(value)}
              >
                <Icon name={icon} />
                <span>
                  <strong>{title}</strong>
                  <small>{hint}</small>
                </span>
                <Icon name="chevron-right" />
              </Button>
            ))}
          </div>
        )}
        <section hidden={mode !== 'import'}>
          <PaneContext.Provider value={{ active: mode === 'import', footer }}>
            <ImportDialog
              initialText={initialText}
              initialDocuments={initialDocuments}
              initialProblems={initialProblems}
              method={method}
              methodChanged={setMethod}
              reviewChanged={setReview}
              Frame={PaneFrame}
              groups={snapshot.groups}
              initialGroup={group}
              targetGroup={group}
              groupChanged={setGroup}
              language={language}
              close={requestClose}
              completed={close}
              changed={changed}
              subscribe={subscribe}
              translateError={translateError}
              onActivity={quickActivity}
            />
          </PaneContext.Provider>
        </section>
        <section hidden={mode !== 'advanced'}>
          {visited && (
            <PaneContext.Provider value={{ active: mode === 'advanced', footer }}>
              <Editor
                libraryRevision={snapshot.libraryRevision}
                Frame={PaneFrame}
                groups={snapshot.groups}
                profiles={snapshot.profiles}
                initialGroup={group}
                targetGroup={group}
                groupChanged={setGroup}
                language={language}
                t={t}
                translateError={translateError}
                close={requestClose}
                completed={close}
                changed={changed}
                onActivity={advancedActivity}
              />
            </PaneContext.Provider>
          )}
        </section>
      </div>
      {confirmClose && (
        <ConfirmDialog
          className="editor-discard"
          title={t('addDiscardTitle')}
          message={t('addDiscardHint')}
          cancelLabel={t('addKeepEditing')}
          confirmLabel={t('addDiscard')}
          cancel={() => {
            setConfirmClose(false);
            requestAnimationFrame(() => focus.current?.focus());
          }}
          confirm={close}
        />
      )}
    </Modal>
  );
}

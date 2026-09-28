import { Button } from '../shared/ui/controls';
import { Icon } from '../ui';
import type { Entry, ResourcesController } from './useResourcesPanel';

/** Move, edit and delete buttons of one DNS server, DNS rule or rule set row. */
export default function ResourceControls({
  controller,
  entry,
  edit,
}: {
  controller: ResourcesController;
  entry: Entry;
  edit(): void;
}) {
  const { tr, disabled, rules, reorder, name, setError, setDeleting } = controller;
  return (
    <div className="route-actions">
      {entry.kind === 'rule' && (
        <>
          <Button
            className="icon-button"
            data-dns-rule-up={entry.index}
            disabled={disabled || !entry.index}
            aria-label={tr('up')}
            onClick={() => reorder(entry.index, -1)}
          >
            <Icon name="arrow-up" />
          </Button>
          <Button
            className="icon-button"
            data-dns-rule-down={entry.index}
            disabled={disabled || entry.index === rules.length - 1}
            aria-label={tr('down')}
            onClick={() => reorder(entry.index, 1)}
          >
            <Icon name="arrow-down" />
          </Button>
        </>
      )}
      <Button
        className="icon-button"
        data-resource-edit={`${entry.kind}:${entry.index}`}
        disabled={disabled}
        aria-label={`${tr('edit')}: ${name(entry)}`}
        onClick={edit}
      >
        <Icon name="edit" />
      </Button>
      <Button
        className="icon-button"
        data-resource-delete={`${entry.kind}:${entry.index}`}
        disabled={disabled}
        aria-label={`${tr('remove')}: ${name(entry)}`}
        onClick={() => {
          setError('');
          setDeleting(entry);
        }}
      >
        <Icon name="trash" />
      </Button>
    </div>
  );
}

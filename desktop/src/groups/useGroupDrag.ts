import useRowDrag from '../shared/ui/useRowDrag';

/** Groups reorder among each other in one list. */
export default function useGroupDrag(
  ids: string[],
  busy: boolean,
  move: (id: string, target: string, after: boolean) => void,
) {
  const drag = useRowDrag<HTMLDivElement>({
    rows: ids.map((id) => [id, 'groups']),
    rowAttribute: 'library-group',
    enabled: !busy && ids.length > 1,
    move,
  });
  return { ...drag, list: drag.root, enabled: !busy && ids.length > 1, end: drag.finish };
}

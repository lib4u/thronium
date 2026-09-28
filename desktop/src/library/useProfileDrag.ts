import type { Profile } from '../api';
import useRowDrag from '../shared/ui/useRowDrag';

/** Profiles reorder within their group. */
export default function useProfileDrag(
  profiles: Pick<Profile, 'id' | 'groupId'>[],
  enabled: boolean,
  move: (id: string, target: string, after: boolean) => void,
) {
  return useRowDrag<HTMLElement>({
    rows: profiles.map((p) => [p.id, p.groupId]),
    rowAttribute: 'order-profile',
    enabled,
    move,
  });
}

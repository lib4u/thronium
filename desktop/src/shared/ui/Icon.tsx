import { iconPaths, type IconName } from './icons';
export type { IconName } from './icons';
export function Icon({ name }: { name: IconName }) {
  return (
    <span className="icon-host">
      <svg
        className="icon"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
        dangerouslySetInnerHTML={{ __html: iconPaths[name] }}
      />
    </span>
  );
}

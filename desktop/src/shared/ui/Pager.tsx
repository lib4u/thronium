import { Button } from './controls';
import { formatNumber } from '../i18n/format.ts';
import { translate } from '../i18n/index.ts';

/** Previous, position and next for a paged list; `page` is zero-based. */
export function Pager({
  page,
  pages,
  language,
  onChange,
  className,
  label,
}: {
  page: number;
  pages: number;
  language: string;
  onChange(page: number): void;
  className: string;
  label?: string;
}) {
  return (
    <nav className={className} aria-label={label}>
      <Button className="button secondary" disabled={page <= 0} onClick={() => onChange(page - 1)}>
        {translate(language, 'common.previous_page')}
      </Button>
      <span>
        {translate(language, 'common.page_position', {
          page: formatNumber(page + 1, language),
          pages: formatNumber(pages, language),
        })}
      </span>
      <Button className="button secondary" disabled={page >= pages - 1} onClick={() => onChange(page + 1)}>
        {translate(language, 'common.next_page')}
      </Button>
    </nav>
  );
}

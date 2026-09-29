// Classes of subscription update job statuses; every view asks here.

/** Still working: waiting, downloading, preparing geodata or checking configurations. */
export const jobActive = (status: string) =>
  ['queued', 'downloading', 'geodata', 'checking'].includes(status);
/** Finished with a changed library or a change waiting for review. */
export const jobChanged = (status: string) => status === 'updated' || status === 'needs-review';
/** Finished in a state the user has to look at. */
export const jobNeedsAttention = (status: string) => status === 'needs-review' || status === 'error';
/** Finished with counts of added, updated, removed and kept profiles. */
export const jobHasCounts = (status: string) => ['updated', 'unchanged', 'needs-review'].includes(status);

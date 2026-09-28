/** The operating system the window runs on, as the webview reports it. */
export type Platform = 'windows' | 'linux' | 'macos' | 'other';

const agent = typeof navigator === 'undefined' ? '' : navigator.userAgent;

export const platform: Platform = /Windows/.test(agent)
  ? 'windows'
  : /Mac OS X|Macintosh/.test(agent)
    ? 'macos'
    : /Linux|X11/.test(agent)
      ? 'linux'
      : 'other';

/** Whether something marked for `platforms` applies here; unmarked applies everywhere. */
export const appliesHere = (platforms?: readonly string[]) => !platforms || platforms.includes(platform);

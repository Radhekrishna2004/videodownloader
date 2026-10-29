// Ported 1:1 from YtDlpService.ALLOWED_URL. Only https links to these exact YouTube/Instagram
// paths are accepted, so arbitrary hosts (SSRF) and non-https schemes can never reach yt-dlp.
const ALLOWED_URL = new RegExp(
  '^https://(?:www\\.|m\\.)?(?:' +
    'instagram\\.com/(?:reel|reels|p|tv)/[A-Za-z0-9_-]+/?' +
    '|instagram\\.com/stories/[A-Za-z0-9_.]+/[0-9]+/?' +
    '|youtube\\.com/watch\\?v=[A-Za-z0-9_-]{11}' +
    '|youtube\\.com/shorts/[A-Za-z0-9_-]{11}' +
    '|youtu\\.be/[A-Za-z0-9_-]{11}' +
    ')(?:[?&#][A-Za-z0-9_=&%.~-]*)?$',
  'i',
);
const INSTAGRAM_URL = /^https:\/\/(?:www\.|m\.)?instagram\.com\//i;

const FACEBOOK_URL = /^https:\/\/(?:(?:www\.|m\.)?facebook\.com|fb\.watch)\//i;

export type Platform = 'instagram' | 'youtube' | 'facebook' | 'x';

const FACEBOOK_ALLOWED = /^https:\/\/(?:www\.|m\.)?(?:facebook\.com\/(?:watch|reel|reels|share|video\.php|video|videos|story\.php|permalink\.php|[A-Za-z0-9.-]+\/(?:videos|posts|reel))|fb\.watch)(?:[/?#][!-~]*)?$/i;
const FACEBOOK_RAW = /^https:\/\/(?:(?:www\.|m\.|web\.|mbasic\.)?facebook\.com|fb\.watch)\//i;

// X (Twitter) posts. Same rule as the others: https only, exact hosts, known paths only.
// X: x.com / twitter.com /<user>/status/<id> (also /i/status/<id>, /i/web/status/<id>, optional /video/1 or /photo/1).
const X_ALLOWED = /^https:\/\/(?:www\.|mobile\.|m\.)?(?:x|twitter)\.com\/(?:i\/web|[A-Za-z0-9_]{1,15})\/status(?:es)?\/[0-9]{1,25}(?:\/(?:video|photo)\/[0-9]{1,2})?\/?(?:[?#][A-Za-z0-9_=&%.~-]*)?$/i;
const X_URL = /^https:\/\/(?:www\.|mobile\.|m\.)?(?:x|twitter)\.com\//i;
/** Facebook share links carry long tracking params: keep only what the video needs (v=ID for /watch and video.php). */
export function normalizeUrl(raw: string): string {
  const t = raw.trim();
  if (!FACEBOOK_RAW.test(t)) return t;
  try {
    const x = new URL(t);
    const keepV = /^\/(?:watch|video\.php)(?:\/|$)/i.test(x.pathname) && x.searchParams.get('v');
    x.hostname = x.hostname.replace(/^(?:web|mbasic)\./i, 'www.');
    x.hash = ''; x.search = keepV ? `?v=${encodeURIComponent(keepV)}` : '';
    return x.toString();
  } catch { return t; }
}

export function isAllowedUrl(url: unknown): url is string {
  if (typeof url !== 'string' || url.length > 300) return false;
  const t = url.trim();
  return ALLOWED_URL.test(t) || FACEBOOK_ALLOWED.test(t) || X_ALLOWED.test(t);
}
export const detectPlatform = (url: string): Platform => (INSTAGRAM_URL.test(url.trim()) ? 'instagram' : FACEBOOK_URL.test(url.trim()) ? 'facebook' : X_URL.test(url.trim()) ? 'x' : 'youtube');

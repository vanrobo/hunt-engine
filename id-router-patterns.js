/**
 * The Hunt Engine — ID router pattern registry.
 * Lightweight pattern → canonical URL templates (no network probes).
 */
"use strict";

(function idRouterPatternsFactory(root) {
  /** @type {Array<{ id: string, label: string, test: (s: string) => boolean, build: (s: string) => Array<{ label: string, url: string }> }>} */
  const ID_ROUTER_PATTERNS = [
    {
      id: "discord_snowflake",
      label: "Discord snowflake",
      test: (s) => /^\d{17,20}$/.test(s),
      build: (s) => [
        {
          label: "Discord message (approx)",
          url: "https://discord.com/channels/@me/" + s,
        },
        { label: "Copy ID", url: "" },
      ],
    },
    {
      id: "youtube_id",
      label: "YouTube video ID",
      test: (s) => /^[A-Za-z0-9_-]{11}$/.test(s),
      build: (s) => [
        { label: "Watch", url: "https://www.youtube.com/watch?v=" + s },
        {
          label: "Comments",
          url: "https://www.youtube.com/watch?v=" + s + "&lc=1",
        },
        { label: "Embed", url: "https://www.youtube.com/embed/" + s },
      ],
    },
    {
      id: "pastebin_id",
      label: "Pastebin ID",
      test: (s) => /^[a-zA-Z0-9]{8}$/.test(s),
      build: (s) => [
        { label: "Pastebin", url: "https://pastebin.com/" + s },
        { label: "Raw", url: "https://pastebin.com/raw/" + s },
      ],
    },
    {
      id: "controlc_id",
      label: "ControlC ID",
      test: (s) => /^[a-f0-9]{32}$/i.test(s),
      build: (s) => [{ label: "ControlC", url: "https://controlc.com/" + s }],
    },
    {
      id: "rentry_slug",
      label: "Rentry slug",
      test: (s) => /^[a-zA-Z0-9_-]{3,64}$/.test(s) && /[a-z]/i.test(s),
      build: (s) => [
        { label: "Rentry", url: "https://rentry.co/" + s },
        { label: "Raw", url: "https://rentry.co/" + s + "/raw" },
      ],
    },
    {
      id: "scratch_id",
      label: "Scratch project",
      test: (s) => /^\d{6,12}$/.test(s),
      build: (s) => [
        { label: "Scratch project", url: "https://scratch.mit.edu/projects/" + s + "/" },
      ],
    },
    {
      id: "genius_annotation",
      label: "Genius annotation",
      test: (s) => /^\d{6,10}$/.test(s),
      build: (s) => [
        { label: "Genius annotation", url: "https://genius.com/annotations/" + s },
      ],
    },
    {
      id: "spotify_track",
      label: "Spotify track ID",
      test: (s) => /^[A-Za-z0-9]{22}$/.test(s),
      build: (s) => [
        { label: "Spotify track", url: "https://open.spotify.com/track/" + s },
      ],
    },
    {
      id: "spotify_playlist",
      label: "Spotify playlist ID",
      test: (s) => /^[A-Za-z0-9]{22}$/.test(s),
      build: (s) => [
        {
          label: "Spotify playlist",
          url: "https://open.spotify.com/playlist/" + s,
        },
      ],
    },
    {
      id: "geohash",
      label: "Geohash",
      test: (s) => /^[0-9bcdefghjkmnpqrstuvwxyz]{4,12}$/i.test(s),
      build: (s) => [
        {
          label: "Geohash decoder",
          url: "https://www.geohash.org/" + s.toLowerCase(),
        },
      ],
    },
    {
      id: "isbn",
      label: "ISBN",
      test: (s) => {
        const c = s.replace(/[-\s]/g, "");
        return /^(?:97[89])?\d{9}[\dXx]$/.test(c);
      },
      build: (s) => {
        const c = s.replace(/[-\s]/g, "");
        return [
          {
            label: "Open Library",
            url: "https://openlibrary.org/isbn/" + encodeURIComponent(c),
          },
          {
            label: "Google Books",
            url:
              "https://www.google.com/search?tbm=bks&q=isbn:" + encodeURIComponent(c),
          },
        ];
      },
    },
    {
      id: "uuid",
      label: "UUID",
      test: (s) =>
        /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          s
        ),
      build: (s) => [{ label: "UUID (copy)", url: "" }],
    },
    {
      id: "ig_highlight",
      label: "Instagram highlight token",
      test: (s) => /^aGl[a-zA-Z0-9+/=]{20,}$/.test(s) || /^\/s\/[a-zA-Z0-9+/=]+/.test(s),
      build: (s) => {
        const token = s.replace(/^\/s\//, "");
        return [
          {
            label: "IG highlight (manual)",
            url: "https://www.instagram.com/s/" + token,
          },
        ];
      },
    },
    {
      id: "wayback_ts",
      label: "Wayback timestamp",
      test: (s) => /^\d{14}$/.test(s),
      build: (s) => [
        {
          label: "Wayback CDX",
          url: "https://web.archive.org/web/" + s + "/*",
        },
      ],
    },
    {
      id: "reddit_id",
      label: "Reddit post ID",
      test: (s) => /^[a-z0-9]{6,7}$/i.test(s),
      build: (s) => [
        { label: "Reddit comments", url: "https://www.reddit.com/comments/" + s },
      ],
    },
    {
      id: "gist_id",
      label: "GitHub Gist",
      test: (s) => /^[a-f0-9]{32}$/i.test(s),
      build: (s) => [{ label: "Gist", url: "https://gist.github.com/raw/" + s }],
    },
    {
      id: "google_doc",
      label: "Google Doc ID",
      test: (s) => /^[a-zA-Z0-9_-]{25,50}$/.test(s) && /[A-Z]/.test(s) && /[a-z]/.test(s),
      build: (s) => [
        { label: "Google Doc", url: "https://docs.google.com/document/d/" + s + "/edit" },
      ],
    },
  ];

  function matchIdPatterns(raw) {
    const text = String(raw || "").trim();
    if (!text) return [];
    const hits = [];
    for (const pat of ID_ROUTER_PATTERNS) {
      try {
        if (pat.test(text)) {
          hits.push({
            id: pat.id,
            label: pat.label,
            token: text,
            links: pat.build(text).filter((l) => l.url || l.label === "Copy ID"),
          });
        }
      } catch (_err) {
        /* skip */
      }
    }
    return hits;
  }

  function matchIdPatternsBest(raw) {
    const all = matchIdPatterns(raw);
    if (all.length <= 1) return all;
    const text = String(raw || "").trim();
    return all.filter((h) => {
      if (h.id === "reddit_id" && /^\d+$/.test(text)) return false;
      if (h.id === "scratch_id" && text.length > 12) return false;
      if (h.id === "genius_annotation" && text.length > 10) return false;
      return true;
    });
  }

  const api = { ID_ROUTER_PATTERNS, matchIdPatterns, matchIdPatternsBest };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  } else {
    root.IdRouterPatterns = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : typeof self !== "undefined" ? self : this);

# Fonts

The brand guide specifies **DM Sans** (product and body) and **IBM Plex Mono**
(technical labels). Both are licensed under the SIL Open Font License 1.1, which
permits embedding in an application. Licence texts: `OFL-DMSans.txt`,
`OFL-IBMPlexMono.txt`.

## Files in this beta

| File | Internal family name | Source |
| --- | --- | --- |
| DMSans-Regular / Medium / Bold.ttf | DM Sans 9pt | Fontsource `@fontsource/dm-sans` 5.3.0, Latin subset, WOFF2 decompressed to TTF |
| IBMPlexMono-Regular / Medium.ttf | IBM Plex Mono | Fontsource `@fontsource/ibm-plex-mono` 5.3.0, Latin subset, WOFF2 decompressed to TTF |

`Theme.xaml` references them as `#DM Sans 9pt` and `#IBM Plex Mono`, with
Segoe UI and Consolas as fallbacks. Text outside the Latin subset falls back
automatically.

## Before public release

Replace these with the official full TTF releases (googlefonts/dm-fonts and
IBM/plex on GitHub). This avoids any question about subsetting under the
licence's Reserved Font Name terms (IBM Plex reserves the name "Plex").
Update the family name in `Theme.xaml` if it differs.

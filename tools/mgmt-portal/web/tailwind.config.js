/**
 * Tailwind theme — semantic token mapping for the ClaudIA 5GC Management Portal.
 *
 * Every value below points at a CSS variable declared in `src/index.css` for
 * BOTH light (`:root`) and dark (`.dark`) themes. Components consume the
 * resulting semantic utilities (`bg-card`, `text-muted-fg`, `border-border`,
 * `text-success-fg`, …) — never raw palette utilities (`bg-gray-900`).
 *
 * The default Tailwind palette is deliberately left available (`extend`) so the
 * not-yet-migrated pages keep building during the phased rollout; the
 * token-enforcement audit in `STYLE_GUIDE.md` is what keeps pages honest.
 *
 * @type {import('tailwindcss').Config}
 */

/** Map a channel-triplet CSS variable to a Tailwind colour with opacity support. */
const token = (variable) => `rgb(var(${variable}) / <alpha-value>)`

export default {
  darkMode: 'class',
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        // Surfaces & text
        bg: token('--c-bg'),
        fg: token('--c-fg'),
        card: {
          DEFAULT: token('--c-card'),
          fg: token('--c-card-fg'),
        },
        muted: {
          DEFAULT: token('--c-muted'),
          fg: token('--c-muted-fg'),
        },
        border: {
          DEFAULT: token('--c-border'),
          strong: token('--c-border-strong'),
        },
        input: {
          DEFAULT: token('--c-input'),
          border: token('--c-input-border'),
        },
        ring: token('--c-ring'),

        // Brand
        primary: {
          DEFAULT: token('--c-primary'),
          fg: token('--c-primary-fg'),
          // `primary` is a *fill*; as text the dark theme needs a lighter blue.
          // Use `text-primary-text` for links / coloured words (7.0:1 dark).
          text: token('--c-primary-text'),
        },
        secondary: {
          DEFAULT: token('--c-secondary'),
          fg: token('--c-secondary-fg'),
        },
        accent: {
          DEFAULT: token('--c-accent'),
          fg: token('--c-accent-fg'),
          // `accent` is a fill / large-figure colour (3.4:1 on the light page);
          // `text-accent-text` is the body-safe accent (7.0:1 light, 7.9:1 dark).
          text: token('--c-accent-text'),
        },

        // Semantic actions
        destructive: {
          DEFAULT: token('--c-destructive'),
          fg: token('--c-destructive-fg'),
        },

        // Semantic status (fg shown on the page surface; surface/border for badges)
        success: {
          DEFAULT: token('--c-success-fg'),
          fg: token('--c-success-fg'),
          surface: token('--c-success-surface'),
          border: token('--c-success-border'),
        },
        warning: {
          DEFAULT: token('--c-warning-fg'),
          fg: token('--c-warning-fg'),
          surface: token('--c-warning-surface'),
          border: token('--c-warning-border'),
        },
        danger: {
          DEFAULT: token('--c-danger-fg'),
          fg: token('--c-danger-fg'),
          surface: token('--c-danger-surface'),
          border: token('--c-danger-border'),
        },
        info: {
          DEFAULT: token('--c-info-fg'),
          fg: token('--c-info-fg'),
          surface: token('--c-info-surface'),
          border: token('--c-info-border'),
        },

        // Log / terminal surfaces
        log: {
          bg: token('--c-log-bg'),
          fg: token('--c-log-fg'),
        },

        // Overlay scrim (always used with an alpha modifier, e.g. bg-overlay/50)
        overlay: token('--c-overlay'),

        // Chart series
        chart: {
          1: token('--c-chart-1'),
          2: token('--c-chart-2'),
          3: token('--c-chart-3'),
          4: token('--c-chart-4'),
          5: token('--c-chart-5'),
        },
      },

      // Bare `border` / `ring` utilities resolve to the semantic tokens.
      borderColor: {
        DEFAULT: token('--c-border'),
      },
      ringColor: {
        DEFAULT: token('--c-ring'),
      },

      fontFamily: {
        // Projector-safe: no light (300) weights anywhere.
        sans: [
          'Fira Sans',
          'ui-sans-serif',
          'system-ui',
          '-apple-system',
          'Segoe UI',
          'Roboto',
          'Helvetica Neue',
          'Arial',
          'sans-serif',
        ],
        mono: [
          'Fira Code',
          'ui-monospace',
          'Cascadia Code',
          'JetBrains Mono',
          'SFMono-Regular',
          'Menlo',
          'Consolas',
          'monospace',
        ],
      },

      borderRadius: {
        card: '0.5rem',
        control: '0.375rem',
      },

      boxShadow: {
        card: '0 1px 2px 0 rgb(0 0 0 / 0.06), 0 1px 3px 0 rgb(0 0 0 / 0.04)',
        overlay: '0 16px 40px -12px rgb(0 0 0 / 0.45)',
      },

      // Subtle motion only (Q3: 150–300 ms); reduced-motion is handled globally.
      transitionDuration: {
        DEFAULT: '200ms',
      },
    },
  },
  plugins: [],
}

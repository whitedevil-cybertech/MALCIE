# MALCIE Design System

## Executive Summary  
The MALCIE UI follows a clean, modern security-product aesthetic with strong emphasis on accessibility. We define a consistent color palette (light and dark variants) using CSS variables, an 8px-based spacing scale, and clear typography scales. All color contrasts meet WCAG AA (≥4.5:1 for normal text). We use open-source fonts with sensible fallbacks. This document provides detailed design tokens (JSON, CSS/SCSS) and guidelines for colors, typography, spacing, and icon usage, ensuring MALCIE’s interface is clear, cohesive, and accessible.

## Color Palette & Theme

We use distinct color roles (primary, secondary, success, warning, error, neutral, etc.) with accessible contrasts. All text meets **WCAG AA**: at least 4.5:1 contrast for body text and ≥3:1 for large text. We avoid relying on red/green alone (color blindness affects ~1 in 12 men) and always pair colors with icons or shapes.

| Role             | Light Theme (HEX) | Dark Theme (HEX) | Usage Examples                    |
|------------------|-------------------|------------------|-----------------------------------|
| Background       | `#FFFFFF`         | `#121212`        | App background                    |
| Surface (cards)  | `#F4F5F6`         | `#1E1E1E`        | Panels, cards                     |
| Text – Primary   | `#212121`         | `#E0E0E0`        | Main text (headings, body)        |
| Text – Secondary | `#535353`         | `#BDBDBD`        | Secondary text, captions          |
| Primary (brand)  | `#1976D2`         | `#90CAF9`        | Primary buttons, links, highlights|
| Secondary/Accent | `#FFC107`         | `#FFD54F`        | Highlights, badges, links         |
| Success          | `#388E3C`         | `#81C784`        | Success messages, badges          |
| Warning          | `#FFA000`         | `#FFD54F`        | Warnings (e.g. caution banners)   |
| Error (Danger)   | `#D32F2F`         | `#EF5350`        | Error messages, alerts            |
| Info             | `#0288D1`         | `#29B6F6`        | Informational messages, highlights|

For **light theme**, backgrounds are white/light-gray with dark text. For **dark theme**, backgrounds are near-black with light text. Accent colors (blue, amber, green, red) are chosen for semantic roles. Always use white text on colored surfaces if needed (e.g. white on `--color-primary`), but verify contrast (e.g. blue on white fails 4.5:1, so use dark text on light surfaces).

### CSS Variables Example  
Define variables for light and dark modes (can use `[data-theme="dark"]` or a CSS class):
```css
:root { /* Light Theme */ 
  --color-bg: #FFFFFF;
  --color-surface: #F4F5F6;
  --color-text-primary: #212121;
  --color-text-secondary: #535353;
  --color-primary: #1976D2;
  --color-secondary: #FFC107;
  --color-success: #388E3C;
  --color-warning: #FFA000;
  --color-error: #D32F2F;
  --color-info: #0288D1;
}
[data-theme="dark"] {
  --color-bg: #121212;
  --color-surface: #1E1E1E;
  --color-text-primary: #E0E0E0;
  --color-text-secondary: #BDBDBD;
  --color-primary: #90CAF9;
  --color-secondary: #FFD54F;
  --color-success: #81C784;
  --color-warning: #FFD54F;
  --color-error: #EF5350;
  --color-info: #29B6F6;
}
```
Use these variables in your CSS/JS. For example, in Chart.js or similar charting libraries: 
```css
.chart-bar { background-color: var(--color-primary); }
.alert-error { background-color: var(--color-error); color: #fff; }
.timeline-event { color: var(--color-secondary); }
```
This ensures consistency and easy theming. Always test with tools (e.g. WebAIM Contrast Checker) to confirm AA compliance.

## Fonts

Use modern, readable sans-serif fonts for UI, and monospace for code. Recommended font stacks with fallbacks:

- **UI Font (sans-serif):**  
  `font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;`  
  *Why Inter?* It’s open-source (SIL Open Font License), optimized for screen legibility. Fallback to system fonts ensures fast loads.

- **Monospace (code):**  
  `font-family: 'Source Code Pro', 'Menlo', 'Consolas', 'Courier New', monospace;`  
  *Why Source Code Pro?* Also open-source (OFL) and widely used. This stack falls back to common monospace fonts.

All Google Fonts are free and open-source (typically SIL OFL or Apache 2.0), so they can be used in any project. Ensure proper font loading (preconnect, preload or local install) for performance. For icon text or special UI, use consistent semantic fonts (see typography below).

## Typography

Define a clear scale for headings, body, and captions. Below is a sample typographic scale; adjust slightly if needed. Values are in pixels (px) and rem (1rem = 16px). Line-heights and letter-spacing meet accessibility (e.g. WCAG recommends ≥1.5 line-height, letter-spacing ≥0.12em for readability when scaled).

| Style           | Font Size  | Line-Height | Font-Weight | Letter-Spacing | Example Use           |
|-----------------|------------|-------------|-------------|----------------|-----------------------|
| **H1**          | 2.25rem<br>(36px) | 2.75rem     | 700         | 0em            | Page titles           |
| **H2**          | 1.75rem<br>(28px) | 2.25rem     | 600         | 0em            | Section headings      |
| **H3**          | 1.5rem<br>(24px)  | 2.0rem      | 600         | 0em            | Sub-section headings  |
| **H4**          | 1.25rem<br>(20px) | 1.75rem     | 500         | 0em            | Smaller headings      |
| **H5**          | 1.125rem<br>(18px)| 1.5rem      | 500         | 0.01em         | Tertiary headings    |
| **H6**          | 1rem<br>(16px)    | 1.5rem      | 500         | 0.02em         | Minor headings/titles |
| **Body / P**    | 1rem<br>(16px)    | 1.5rem      | 400         | 0em            | Normal paragraph text |
| **Small/Caption** | 0.875rem<br>(14px) | 1.25rem   | 400         | 0em            | Labels, captions       |

- **Line-height:** At least 1.5× font-size for body text (per SC 1.4.12). This improves readability. 
- **Font-weight:** Use semibold or bold for headings and normal for body. Avoid very thin weights on small text.
- **Letter-spacing:** Default 0–0.02em is fine. WCAG suggests user-overridable letter-spacing up to 0.12em. For tracking (e.g. button text), ~0.05em can help legibility. 
- **Contrast:** Body text should have ≥4.5:1 contrast vs background. Headings (if ≥24px) need ≥3:1. 

Use consistent scales (e.g. doubling or golden ratio) so text hierarchy is clear. In React/TypeScript (CSS-in-JS) you might use:
```js
const styles = {
  heading1: {
    fontSize: '2.25rem',
    lineHeight: '2.75rem',
    fontWeight: 700,
  },
  body: {
    fontSize: '1rem',
    lineHeight: '1.5rem',
    fontWeight: 400,
  },
  // ...
};
```
or in plain CSS:
```css
h1 { font-size: 2.25rem; line-height: 2.75rem; font-weight: 700; }
p  { font-size: 1rem;  line-height: 1.5rem;  font-weight: 400; }
```

## Design Tokens & Examples

Design tokens (in JSON) and CSS/SCSS variables ensure consistency. Example token definitions (colors and spacing):

```json
// design-tokens.json
{
  "color": {
    "background": { "value": "#FFFFFF", "comment": "Light background" },
    "surface":    { "value": "#F4F5F6" },
    "text-primary":   { "value": "#212121" },
    "text-secondary": { "value": "#535353" },
    "primary":    { "value": "#1976D2", "comment": "Brand blue" },
    "secondary":  { "value": "#FFC107" },
    "success":    { "value": "#388E3C" },
    "warning":    { "value": "#FFA000" },
    "error":      { "value": "#D32F2F" },
    "info":       { "value": "#0288D1" }
  },
  "space": {
    "base": { "value": "8px" },
    "small": { "value": "4px" },
    "medium": { "value": "16px" },
    "large": { "value": "24px" }
  },
  "font": {
    "family": {
      "ui": { "value": "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" },
      "mono": { "value": "Source Code Pro, Menlo, Consolas, monospace" }
    },
    "size": {
      "body":    { "value": "1rem" },
      "h1":      { "value": "2.25rem" },
      "h2":      { "value": "1.75rem" },
      "caption": { "value": "0.875rem" }
    }
  }
}
```
And corresponding SCSS variables:
```scss
:root {
  --space-base: 8px;
  --space-small: 4px;
  --space-medium: 16px;
  --space-large: 24px;

  --font-ui: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-mono: 'Source Code Pro', Menlo, Consolas, monospace;
  --font-size-body: 1rem;
  --font-size-h1: 2.25rem;

  --color-background: #FFFFFF;
  --color-surface: #F4F5F6;
  --color-text-primary: #212121;
  --color-text-secondary: #535353;
  --color-primary: #1976D2;
  --color-secondary: #FFC107;
  --color-success: #388E3C;
  --color-warning: #FFA000;
  --color-error: #D32F2F;
  --color-info: #0288D1;
}
[data-theme="dark"] {
  --color-background: #121212;
  --color-surface: #1E1E1E;
  --color-text-primary: #E0E0E0;
  /* ... other dark overrides ... */
}
```
Use tokens in code to ensure consistency. For example, spacing tokens (`--space-medium`) align layout to an 8px grid. Font-size tokens make global font updates simple.

## Style Guide: Do’s & Don’ts

- **Do** ensure high contrast. All text/colors meet WCAG AA (≥4.5:1). Use light text on dark backgrounds or vice versa.  
- **Don’t** rely on color alone to convey meaning. Always pair status colors with icons, labels, or patterns (e.g. a warning triangle for caution, not just amber color).

- **Do** use consistent spacing multiples (8px base). For example, use 8px, 16px, 24px, etc., for margins/padding to maintain rhythm.  
- **Don’t** use arbitrary pixel gaps or inconsistent spacing that breaks alignment.

- **Do** use meaningful, easily-recognizable icons with text labels. Maintain one icon style (e.g. outline style, 16px grid) throughout. Atlassian uses 16×16px icons for primary UI.  
- **Don’t** create new icons for common metaphors (use existing ones) and avoid excessive detail. Icons should be simple, legible, and supported by text.

- **Do** test colorblind accessibility (avoid red/green-only signals). Ensure interactive elements meet contrast.  
- **Do** maintain a clear visual hierarchy: headings are bolder/larger, buttons use brand colors, secondary actions use neutral tones. Use the right color role for the context (e.g. use **Success** green for success states, **Danger** red for errors).

- **Don’t** use very low-contrast text (e.g. grey on grey).  
- **Don’t** overcrowd the interface—prioritize whitespace and clear grouping.  

By following these guidelines and using the provided tokens, the MALCIE UI will be **consistent, accessible, and professional**. Proper theming and typography ensure it’s easy to implement in React/TypeScript while meeting security-product aesthetic and WCAG standards.

**Key References:** WCAG 2.1 contrast requirements; WCAG text spacing (line-height ≥1.5); accessible design best practices; Atlassian design tokens; Google Fonts licensing.
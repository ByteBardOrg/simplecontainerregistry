---
name: Technical Registry UI
colors:
  surface: '#faf8ff'
  surface-dim: '#dad9e1'
  surface-bright: '#faf8ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#f4f3fa'
  surface-container: '#eeedf4'
  surface-container-high: '#e9e7ef'
  surface-container-highest: '#e3e1e9'
  on-surface: '#1a1b21'
  on-surface-variant: '#444651'
  inverse-surface: '#2f3036'
  inverse-on-surface: '#f1f0f7'
  outline: '#757682'
  outline-variant: '#c5c5d3'
  surface-tint: '#4059aa'
  primary: '#00236f'
  on-primary: '#ffffff'
  primary-container: '#1e3a8a'
  on-primary-container: '#90a8ff'
  inverse-primary: '#b6c4ff'
  secondary: '#505f76'
  on-secondary: '#ffffff'
  secondary-container: '#d0e1fb'
  on-secondary-container: '#54647a'
  tertiary: '#4b1c00'
  on-tertiary: '#ffffff'
  tertiary-container: '#6e2c00'
  on-tertiary-container: '#f39461'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#dce1ff'
  primary-fixed-dim: '#b6c4ff'
  on-primary-fixed: '#00164e'
  on-primary-fixed-variant: '#264191'
  secondary-fixed: '#d3e4fe'
  secondary-fixed-dim: '#b7c8e1'
  on-secondary-fixed: '#0b1c30'
  on-secondary-fixed-variant: '#38485d'
  tertiary-fixed: '#ffdbcb'
  tertiary-fixed-dim: '#ffb691'
  on-tertiary-fixed: '#341100'
  on-tertiary-fixed-variant: '#773205'
  background: '#faf8ff'
  on-background: '#1a1b21'
  surface-variant: '#e3e1e9'
typography:
  display-lg:
    fontFamily: Geist
    fontSize: 48px
    fontWeight: '600'
    lineHeight: 56px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Geist
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.01em
  headline-lg-mobile:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
  headline-md:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '500'
    lineHeight: 32px
  body-lg:
    fontFamily: Inter
    fontSize: 18px
    fontWeight: '400'
    lineHeight: 28px
  body-md:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
  body-sm:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
  label-md:
    fontFamily: Geist
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: 0.01em
  label-sm:
    fontFamily: Geist
    fontSize: 12px
    fontWeight: '600'
    lineHeight: 16px
rounded:
  sm: 0.25rem
  DEFAULT: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  full: 9999px
spacing:
  base: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  xxl: 48px
  gutter: 24px
  margin-mobile: 16px
  margin-desktop: 32px
  max-width: 1440px
---

## Brand & Style
The design system is engineered for high-density technical environments where clarity, speed of recognition, and professional trust are paramount. The brand personality is "The Quiet Expert"—sophisticated but never flashy, prioritizing the user's data over the interface itself.

The aesthetic follows a **Modern SaaS** movement: a blend of high-utility minimalism and subtle elevation. It utilizes a restrained palette, generous whitespace to reduce cognitive load, and a strict adherence to a systematic grid. The goal is to create a digital workspace that feels precise, stable, and effortless to navigate.

## Colors
This design system utilizes a "Foundation Blue" as its primary anchor to evoke stability and technical authority. 

- **Primary:** Deep Indigo (#1E3A8A) used for primary actions, active states, and brand touchpoints.
- **Neutrals:** A range of Slate grays provides the structural framework. Backgrounds use a very soft cool-gray (#F8FAFC) to differentiate from pure white (#FFFFFF) surfaces.
- **Semantic:** Success, Warning, and Error colors are used sparingly for status indicators and validation, ensuring they stand out against the neutral backdrop.
- **Borders:** Low-contrast grays (#E2E8F0) define boundaries without creating visual noise.

## Typography
The system employs a dual-sans-serif approach. **Geist** is used for headlines and labels to provide a technical, slightly geometric edge that feels modern and precise. **Inter** is the workhorse for body text and data entry, selected for its exceptional legibility at small sizes and high-density layouts.

Emphasis is placed on a clear vertical rhythm. Use `label-sm` for table headers and metadata descriptors, always in a medium or semi-bold weight to maintain hierarchy against standard body text.

## Layout & Spacing
The layout follows a **Fixed-Fluid Hybrid** model. Content is centered within a 1440px max-width container for readability on ultra-wide monitors, while fluidly scaling down to mobile widths. 

A 12-column grid is standard for desktop layouts, with 24px gutters. Spacing follows a strict 4px base-unit system. Elements like stat cards should use `lg` (24px) internal padding to maintain the "fresh and simple" feel, ensuring that technical data has room to breathe. On mobile, margins reduce to 16px to maximize horizontal real estate for data tables.

## Elevation & Depth
Depth in this system is achieved through **Tonal Layers** and extremely subtle **Ambient Shadows**. 

1.  **Level 0 (Base):** The main background (#F8FAFC).
2.  **Level 1 (Surface):** White cards (#FFFFFF) with a 1px border (#E2E8F0). No shadow. This is used for standard registry lists.
3.  **Level 2 (Elevated):** White cards with a subtle, diffused shadow (0px 4px 12px rgba(0,0,0,0.05)). Used for hover states on clickable cards or stat summaries that need focus.
4.  **Level 3 (Overlay):** Modals and dropdowns. Use a stronger shadow (0px 12px 24px rgba(0,0,0,0.1)) and a background blur of 8px on the overlay backdrop to maintain context without visual clutter.

## Shapes
The design system uses a "Rounded" shape language (0.5rem / 8px). This radius is applied consistently to buttons, input fields, and cards to soften the technical nature of the application without appearing childish or overly "bubbly." Larger components like main content containers or large modals may use `rounded-lg` (16px) for a more pronounced structural feel.

## Components
- **Buttons:** Primary buttons use a solid Primary Blue fill with white text. Secondary buttons use a 1px border with Primary Blue text. No gradients. Hover states should simply darken the fill by 10%.
- **Data Tables:** Headers use `label-sm` with a light gray background (#F1F5F9) and subtle bottom border. Rows have a fixed height (minimum 52px) to ensure touch targets and legibility. Use alternating row stripes only if data exceeds 15 columns.
- **Stat Cards:** Use a simple white surface with a 1px border. The value should be in `headline-md` and the label in `label-sm` (Slate 500).
- **Forms:** Input fields use a 1px border. Focus states use a 2px Primary Blue border with a soft blue outer glow. Labels are positioned above the field for maximum clarity.
- **Chips/Badges:** Use a "soft-fill" approach—lightly tinted backgrounds with darker text (e.g., Success green text on a 10% opacity green background) for status indicators.

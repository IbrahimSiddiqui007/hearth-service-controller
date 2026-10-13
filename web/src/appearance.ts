export type Appearance = {
  theme: 'light' | 'dark' | 'system';
  accent: 'sage' | 'teal' | 'violet' | 'amber';
  density: 'comfortable' | 'compact';
  textSize: 'standard' | 'large' | 'larger';
  reduceMotion: boolean;
};

export const appearanceDefaults: Appearance = {
  theme: 'light', accent: 'sage', density: 'comfortable', textSize: 'standard', reduceMotion: false,
};
export const appearanceKey = 'psc-appearance-v1';

export function readAppearance(): Appearance {
  try {
    const saved = JSON.parse(localStorage.getItem(appearanceKey) || '{}');
    return {
      theme: ['light', 'dark', 'system'].includes(saved.theme) ? saved.theme : appearanceDefaults.theme,
      accent: ['sage', 'teal', 'violet', 'amber'].includes(saved.accent) ? saved.accent : appearanceDefaults.accent,
      density: ['comfortable', 'compact'].includes(saved.density) ? saved.density : appearanceDefaults.density,
      textSize: ['standard', 'large', 'larger'].includes(saved.textSize) ? saved.textSize : appearanceDefaults.textSize,
      reduceMotion: typeof saved.reduceMotion === 'boolean' ? saved.reduceMotion : false,
    };
  } catch { return { ...appearanceDefaults }; }
}

export function applyAppearance(preferences: Appearance, systemDark: boolean) {
  const root = document.documentElement;
  root.dataset.theme = preferences.theme === 'system' ? (systemDark ? 'dark' : 'light') : preferences.theme;
  root.dataset.accent = preferences.accent;
  root.dataset.density = preferences.density;
  root.dataset.textSize = preferences.textSize;
  root.dataset.reduceMotion = String(preferences.reduceMotion);
  root.style.colorScheme = root.dataset.theme;
}

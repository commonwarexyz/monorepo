export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "commonware-chat-theme";

export function parseTheme(value: string | null): Theme | undefined {
  return value === "light" || value === "dark" ? value : undefined;
}

export function effectiveTheme(preference: Theme | undefined, prefersDark: boolean): Theme {
  return preference ?? (prefersDark ? "dark" : "light");
}

export function installThemeToggle(button: HTMLButtonElement): void {
  const systemPreference = window.matchMedia("(prefers-color-scheme: dark)");
  let preference = readPreference();

  const render = (): void => {
    const theme = effectiveTheme(preference, systemPreference.matches);
    document.documentElement.dataset.theme = theme;
    button.dataset.theme = theme;
    button.setAttribute("aria-pressed", String(theme === "dark"));
    button.setAttribute("aria-label", `Switch to ${theme === "light" ? "dark" : "light"} mode`);
    button.title = `Switch to ${theme === "light" ? "dark" : "light"} mode`;
    updateThemeColor(theme);
  };

  button.addEventListener("click", () => {
    const current = effectiveTheme(preference, systemPreference.matches);
    preference = current === "light" ? "dark" : "light";
    writePreference(preference);
    render();
  });
  systemPreference.addEventListener("change", () => {
    if (!preference) {
      render();
    }
  });
  render();
}

function readPreference(): Theme | undefined {
  try {
    return parseTheme(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch {
    return undefined;
  }
}

function writePreference(theme: Theme): void {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // The active page still changes theme when storage is unavailable.
  }
}

function updateThemeColor(theme: Theme): void {
  const meta = document.querySelector<HTMLMetaElement>('meta[name="theme-color"]');
  meta?.setAttribute("content", theme === "dark" ? "#11120f" : "#f2f0e9");
}

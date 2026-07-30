interface ClipboardWriter {
  writeText(text: string): Promise<void>;
}

type LegacyCopy = (text: string) => boolean;

export async function copyText(
  text: string,
  clipboard: ClipboardWriter | null = secureClipboard(),
  fallback: LegacyCopy = legacyCopy,
): Promise<void> {
  if (clipboard) {
    try {
      await clipboard.writeText(text);
      return;
    } catch {
      // Older and permission-restricted browsers may still support synchronous copying.
    }
  }

  if (!fallback(text)) {
    throw new Error("Could not copy to the clipboard.");
  }
}

function secureClipboard(): ClipboardWriter | null {
  if (typeof window === "undefined" || !window.isSecureContext || !navigator.clipboard?.writeText) {
    return null;
  }
  return navigator.clipboard;
}

function legacyCopy(text: string): boolean {
  const activeElement = document.activeElement instanceof HTMLElement ? document.activeElement : undefined;
  const selection = window.getSelection();
  const ranges = selection ? Array.from({ length: selection.rangeCount }, (_, index) => selection.getRangeAt(index)) : [];
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.contentEditable = "true";
  textarea.style.position = "fixed";
  textarea.style.top = "0";
  textarea.style.left = "0";
  textarea.style.width = "1px";
  textarea.style.height = "1px";
  textarea.style.fontSize = "16px";
  textarea.style.opacity = "0";
  document.body.append(textarea);
  textarea.focus({ preventScroll: true });
  textarea.select();
  textarea.setSelectionRange(0, text.length);

  try {
    return document.execCommand("copy");
  } finally {
    textarea.remove();
    selection?.removeAllRanges();
    for (const range of ranges) {
      selection?.addRange(range);
    }
    activeElement?.focus({ preventScroll: true });
  }
}

import "./styles.css";
import { createBrowserChat, type BrowserP2pSession, type ChatEvent, type ConnectionState } from "./bridge";
import { parsePairingPayload, serializePairingPayload } from "./pairing";

const elements = {
  composer: getElement<HTMLFormElement>("composer"),
  connectButton: getElement<HTMLButtonElement>("connect-button"),
  emptyState: getElement<HTMLLIElement>("empty-state"),
  identity: getElement<HTMLButtonElement>("identity"),
  messageInput: getElement<HTMLTextAreaElement>("message-input"),
  messages: getElement<HTMLOListElement>("messages"),
  notice: getElement<HTMLDivElement>("notice"),
  noticeDetail: getElement<HTMLParagraphElement>("notice-detail"),
  noticeTitle: getElement<HTMLElement>("notice-title"),
  pairingError: getElement<HTMLParagraphElement>("pairing-error"),
  pairingForm: getElement<HTMLFormElement>("pairing-form"),
  pairingInput: getElement<HTMLInputElement>("pairing-input"),
  reconnectButton: getElement<HTMLButtonElement>("reconnect-button"),
  retryButton: getElement<HTMLButtonElement>("retry-button"),
  sendButton: getElement<HTMLButtonElement>("send-button"),
  statusDot: getElement<HTMLSpanElement>("status-dot"),
  statusText: getElement<HTMLSpanElement>("status-text"),
};

let session: BrowserP2pSession | undefined;
let lastPairingPayload: string | undefined;
let state: ConnectionState = "disconnected";

elements.pairingForm.addEventListener("submit", (event) => {
  event.preventDefault();
  void connect(elements.pairingInput.value);
});

elements.composer.addEventListener("submit", (event) => {
  event.preventDefault();
  void sendMessage();
});

elements.messageInput.addEventListener("input", resizeComposer);
elements.messageInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    elements.composer.requestSubmit();
  }
});

elements.identity.addEventListener("click", () => void copyIdentity());
elements.reconnectButton.addEventListener("click", () => void reconnect());
elements.retryButton.addEventListener("click", () => void initialize());
window.addEventListener("beforeunload", () => session?.free());

void initialize();

async function initialize(): Promise<void> {
  clearNotice();
  elements.retryButton.hidden = true;
  setConnectionState("connecting", "Initializing identity...");

  try {
    session?.free();
    session = await createBrowserChat(handleChatEvent);
    const publicKey = session.publicKey();
    elements.identity.textContent = formatFingerprint(publicKey);
    elements.identity.dataset.publicKey = publicKey;
    elements.identity.disabled = false;
    setConnectionState("disconnected", "Ready to pair");
  } catch (error) {
    session = undefined;
    setConnectionState("disconnected", "WASM unavailable");
    showNotice("Browser networking is unavailable", errorMessage(error));
    elements.retryButton.hidden = false;
  }
}

async function connect(input: string): Promise<void> {
  clearPairingError();
  if (!session) {
    showPairingError("The Commonware WASM bridge is not available.");
    return;
  }

  let payload: string;
  try {
    payload = serializePairingPayload(parsePairingPayload(input));
  } catch (error) {
    showPairingError(errorMessage(error));
    return;
  }

  lastPairingPayload = payload;
  elements.connectButton.disabled = true;
  setConnectionState("connecting");

  try {
    await session.connect(payload);
  } catch (error) {
    setConnectionState("disconnected", "Connection failed");
    showNotice("Could not connect", errorMessage(error));
    elements.reconnectButton.hidden = false;
  } finally {
    elements.connectButton.disabled = false;
  }
}

async function reconnect(): Promise<void> {
  if (!lastPairingPayload) {
    elements.pairingInput.focus();
    return;
  }
  await connect(lastPairingPayload);
}

async function sendMessage(): Promise<void> {
  const text = elements.messageInput.value.trim();
  if (!session || state !== "connected" || !text) {
    return;
  }

  elements.sendButton.disabled = true;
  try {
    await session.send(text);
    appendMessage({ direction: "outgoing", text, timestamp: Date.now() });
    elements.messageInput.value = "";
    resizeComposer();
  } catch (error) {
    showNotice("Message not sent", errorMessage(error));
  } finally {
    elements.sendButton.disabled = state !== "connected";
  }
}

function handleChatEvent(event: ChatEvent): void {
  switch (event.type) {
    case "connection":
      setConnectionState(event.state, connectionLabel(event.state, event.attempt));
      return;
    case "peer":
      clearNotice();
      showNotice("Peer authenticated", formatFingerprint(event.publicKey), "success");
      return;
    case "message":
      appendMessage({ direction: "incoming", text: event.text, timestamp: event.receivedAt });
      return;
    case "error":
      showNotice("Network error", event.message);
      elements.reconnectButton.hidden = !event.recoverable;
  }
}

function setConnectionState(nextState: ConnectionState, label = connectionLabel(nextState)): void {
  state = nextState;
  elements.statusDot.dataset.state = nextState;
  elements.statusText.textContent = label;
  elements.reconnectButton.hidden = nextState !== "disconnected" || !lastPairingPayload;

  const canSend = nextState === "connected";
  elements.messageInput.disabled = !canSend;
  elements.sendButton.disabled = !canSend;
  elements.messageInput.placeholder = canSend ? "Write a message" : "Connect to send a message";
}

function appendMessage(message: {
  direction: "incoming" | "outgoing";
  text: string;
  timestamp: number;
}): void {
  elements.emptyState.remove();

  const item = document.createElement("li");
  item.className = `message ${message.direction}`;

  const body = document.createElement("p");
  body.textContent = message.text;

  const time = document.createElement("time");
  time.dateTime = new Date(message.timestamp).toISOString();
  time.textContent = new Intl.DateTimeFormat(undefined, {
    hour: "numeric",
    minute: "2-digit",
  }).format(message.timestamp);

  item.append(body, time);
  elements.messages.append(item);
  item.scrollIntoView({ behavior: "smooth", block: "end" });
}

async function copyIdentity(): Promise<void> {
  const publicKey = elements.identity.dataset.publicKey;
  if (!publicKey) {
    return;
  }

  await navigator.clipboard.writeText(publicKey);
  const previous = elements.identity.textContent;
  elements.identity.textContent = "Copied public key";
  window.setTimeout(() => {
    elements.identity.textContent = previous;
  }, 1200);
}

function resizeComposer(): void {
  elements.messageInput.style.height = "auto";
  elements.messageInput.style.height = `${Math.min(elements.messageInput.scrollHeight, 132)}px`;
}

function showNotice(title: string, detail: string, tone: "error" | "success" = "error"): void {
  elements.notice.hidden = false;
  elements.notice.dataset.tone = tone;
  elements.noticeTitle.textContent = title;
  elements.noticeDetail.textContent = detail;
}

function clearNotice(): void {
  elements.notice.hidden = true;
  elements.noticeTitle.textContent = "";
  elements.noticeDetail.textContent = "";
}

function showPairingError(message: string): void {
  elements.pairingError.hidden = false;
  elements.pairingError.textContent = message;
  elements.pairingInput.setAttribute("aria-invalid", "true");
}

function clearPairingError(): void {
  elements.pairingError.hidden = true;
  elements.pairingError.textContent = "";
  elements.pairingInput.removeAttribute("aria-invalid");
}

function connectionLabel(connectionState: ConnectionState, attempt?: number): string {
  switch (connectionState) {
    case "connecting":
      return "Connecting...";
    case "connected":
      return "Connected";
    case "reconnecting":
      return attempt ? `Reconnecting · attempt ${attempt}` : "Reconnecting...";
    case "disconnected":
      return "Disconnected";
  }
}

function formatFingerprint(publicKey: string): string {
  const groups = publicKey.match(/.{1,4}/g) ?? [publicKey];
  return `${groups.slice(0, 3).join(" ")} ··· ${groups.slice(-2).join(" ")}`;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function getElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Missing required element #${id}`);
  }
  return element as T;
}

import QRCode from "qrcode";
import "./styles.css";
import { createBrowserChat, type BrowserP2pSession, type ChatEvent, type ConnectionState } from "./bridge";
import { createInvite, inviteUrl, parseInvite, type Invite } from "./invite";
import { loadWebRtcConfig, WebRtcPairing } from "./webrtc";

const elements = {
  composer: getElement<HTMLFormElement>("composer"),
  copyInvite: getElement<HTMLButtonElement>("copy-invite"),
  emptyState: getElement<HTMLLIElement>("empty-state"),
  emptyTitle: getElement<HTMLHeadingElement>("empty-title"),
  emptyDetail: getElement<HTMLParagraphElement>("empty-detail"),
  identity: getElement<HTMLButtonElement>("identity"),
  inviteLink: getElement<HTMLAnchorElement>("invite-link"),
  messageInput: getElement<HTMLTextAreaElement>("message-input"),
  messages: getElement<HTMLOListElement>("messages"),
  notice: getElement<HTMLDivElement>("notice"),
  noticeDetail: getElement<HTMLParagraphElement>("notice-detail"),
  noticeTitle: getElement<HTMLElement>("notice-title"),
  pairing: getElement<HTMLElement>("pairing"),
  pairingDetail: getElement<HTMLParagraphElement>("pairing-detail"),
  pairingTitle: getElement<HTMLElement>("pairing-title"),
  qr: getElement<HTMLImageElement>("invite-qr"),
  qrPanel: getElement<HTMLDivElement>("qr-panel"),
  retryButton: getElement<HTMLButtonElement>("retry-button"),
  sendButton: getElement<HTMLButtonElement>("send-button"),
  statusDot: getElement<HTMLSpanElement>("status-dot"),
  statusText: getElement<HTMLSpanElement>("status-text"),
};

let chat: BrowserP2pSession | undefined;
let pairing: WebRtcPairing | undefined;
let state: ConnectionState = "disconnected";
let currentInviteUrl: string | undefined;

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
elements.copyInvite.addEventListener("click", () => void copyInvite());
elements.retryButton.addEventListener("click", () => void initialize());
window.addEventListener("commonware-pairing-error", (event) => {
  const detail = (event as CustomEvent<unknown>).detail;
  setConnectionState("disconnected", "Connection failed");
  showNotice("Could not connect", errorMessage(detail));
  elements.retryButton.hidden = false;
});
window.addEventListener("beforeunload", cleanup);

void initialize();

async function initialize(): Promise<void> {
  cleanup();
  clearNotice();
  elements.retryButton.hidden = true;
  elements.qrPanel.hidden = true;
  elements.pairing.hidden = false;
  setConnectionState("connecting", "Creating identity");

  let invite: Invite | undefined;
  try {
    invite = parseInvite(new URL(window.location.href));
    if (invite) {
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }

    chat = await createBrowserChat(handleChatEvent);
    const webRtcConfig = await loadWebRtcConfig();
    const publicKey = chat.publicKey();
    elements.identity.textContent = formatFingerprint(publicKey);
    elements.identity.dataset.publicKey = publicKey;
    elements.identity.disabled = false;

    const role = invite ? "responder" : "initiator";
    invite ??= createInvite(publicKey);
    if (role === "initiator") {
      await displayInvite(invite, webRtcConfig.applicationUrl);
      elements.emptyTitle.textContent = "Scan to connect";
      elements.emptyDetail.textContent = "Open the one-time QR on a phone. Signaling is encrypted before it leaves this browser.";
    } else {
      elements.pairingTitle.textContent = "Joining invite";
      elements.pairingDetail.textContent = "Pinning the identity carried by the QR and connecting directly.";
      elements.emptyTitle.textContent = "Connecting to laptop";
      elements.emptyDetail.textContent = "Keep this page open while the browsers establish a direct authenticated channel.";
    }

    pairing = new WebRtcPairing({
      role,
      invite,
      chat,
      iceServers: webRtcConfig.iceServers,
      onState: (label) => setConnectionState("connecting", label),
    });
    await pairing.start();
  } catch (error) {
    setConnectionState("disconnected", "Unavailable");
    showNotice("Could not start pairing", errorMessage(error));
    elements.retryButton.hidden = false;
  }
}

async function displayInvite(invite: Invite, applicationUrl: string): Promise<void> {
  currentInviteUrl = inviteUrl(invite, new URL(applicationUrl));
  elements.qr.src = await QRCode.toDataURL(currentInviteUrl, {
    width: 220,
    margin: 1,
    color: { dark: "#1c1c1aff", light: "#ffffffff" },
    errorCorrectionLevel: "M",
  });
  elements.inviteLink.href = currentInviteUrl;
  elements.qrPanel.hidden = false;
  elements.pairingTitle.textContent = "Scan once with your phone";
  elements.pairingDetail.textContent = "The QR contains a short-lived pairing secret and this browser's identity.";
}

async function sendMessage(): Promise<void> {
  const text = elements.messageInput.value.trim();
  if (!chat || state !== "connected" || !text) {
    return;
  }

  elements.sendButton.disabled = true;
  try {
    await chat.send(text);
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
      setConnectionState(event.state, connectionLabel(event.state));
      return;
    case "peer":
      currentInviteUrl = undefined;
      elements.pairing.hidden = true;
      elements.emptyTitle.textContent = "You're connected";
      elements.emptyDetail.textContent = "Messages are authenticated and encrypted end to end.";
      clearNotice();
      showNotice("Peer authenticated", formatFingerprint(event.publicKey), "success");
      return;
    case "message":
      appendMessage({
        direction: "incoming",
        sender: event.sender,
        text: event.text,
        timestamp: event.receivedAt,
      });
      return;
    case "error":
      showNotice("Connection error", event.message);
      elements.retryButton.hidden = !event.recoverable;
  }
}

function setConnectionState(nextState: ConnectionState, label = connectionLabel(nextState)): void {
  state = nextState;
  elements.statusDot.dataset.state = nextState;
  elements.statusText.textContent = label;
  const canSend = nextState === "connected";
  elements.messageInput.disabled = !canSend;
  elements.sendButton.disabled = !canSend;
  elements.messageInput.placeholder = canSend ? "Write a message" : "Connect to send a message";
}

function appendMessage(message: {
  direction: "incoming" | "outgoing";
  sender?: string;
  text: string;
  timestamp: number;
}): void {
  elements.emptyState.remove();
  const item = document.createElement("li");
  item.className = `message ${message.direction}`;
  if (message.sender) {
    const sender = document.createElement("span");
    sender.className = "message-sender";
    sender.textContent = formatFingerprint(message.sender);
    item.append(sender);
  }
  const body = document.createElement("p");
  body.textContent = message.text;
  const time = document.createElement("time");
  time.dateTime = new Date(message.timestamp).toISOString();
  time.textContent = new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(message.timestamp);
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
  temporarilyLabel(elements.identity, "Copied public key");
}

async function copyInvite(): Promise<void> {
  if (!currentInviteUrl) {
    return;
  }
  await navigator.clipboard.writeText(currentInviteUrl);
  temporarilyLabel(elements.copyInvite, "Copied");
}

function temporarilyLabel(element: HTMLElement, label: string): void {
  const previous = element.textContent;
  element.textContent = label;
  window.setTimeout(() => {
    element.textContent = previous;
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

function cleanup(): void {
  pairing?.close();
  pairing = undefined;
  chat?.disconnect();
  chat?.free();
  chat = undefined;
  currentInviteUrl = undefined;
}

function connectionLabel(connectionState: ConnectionState): string {
  switch (connectionState) {
    case "connecting": return "Connecting";
    case "connected": return "Connected directly";
    case "reconnecting": return "Reconnecting";
    case "disconnected": return "Disconnected";
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

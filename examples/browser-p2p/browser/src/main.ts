import QRCode from "qrcode";
import "./styles.css";
import { createBrowserChat, type BrowserP2pSession, type ChatEvent, type ConnectionState } from "./bridge";
import { connectionView } from "./connection-view";
import { createInvite, inviteUrl, parseInvite, type Invite } from "./invite";
import { installThemeToggle } from "./theme";
import { loadWebRtcConfig, WebRtcPairing } from "./webrtc";

const elements = {
  chat: getElement<HTMLElement>("chat"),
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
  pairingHeading: getElement<HTMLDivElement>("pairing-heading"),
  pairingDetail: getElement<HTMLParagraphElement>("pairing-detail"),
  pairingTitle: getElement<HTMLElement>("pairing-title"),
  qr: getElement<HTMLImageElement>("invite-qr"),
  qrPanel: getElement<HTMLDivElement>("qr-panel"),
  retryButton: getElement<HTMLButtonElement>("retry-button"),
  sendButton: getElement<HTMLButtonElement>("send-button"),
  statusDot: getElement<HTMLSpanElement>("status-dot"),
  statusText: getElement<HTMLSpanElement>("status-text"),
  themeToggle: getElement<HTMLButtonElement>("theme-toggle"),
};

let chat: BrowserP2pSession | undefined;
let pairing: WebRtcPairing | undefined;
let state: ConnectionState = "disconnected";
let currentInviteUrl: string | undefined;

installThemeToggle(elements.themeToggle);
installViewportSync();

elements.composer.addEventListener("submit", (event) => {
  event.preventDefault();
  void sendMessage();
});
elements.messageInput.addEventListener("input", resizeComposer);
elements.messageInput.addEventListener("keydown", (event) => {
  if (
    event.key === "Enter" &&
    !event.shiftKey &&
    !event.isComposing &&
    !window.matchMedia("(pointer: coarse)").matches
  ) {
    event.preventDefault();
    elements.composer.requestSubmit();
  }
});
elements.messageInput.addEventListener("focus", () => requestAnimationFrame(() => scrollMessagesToEnd(false)));
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
  elements.chat.dataset.view = "pairing";
  elements.retryButton.hidden = true;
  elements.qrPanel.hidden = true;
  elements.pairingHeading.hidden = false;
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
      onDisconnect: handlePeerDisconnected,
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
  elements.pairingHeading.hidden = true;
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
    case "connection": {
      const peerDisconnected = setConnectionState(event.state);
      if (peerDisconnected) {
        presentPeerDisconnected();
      }
      return;
    }
    case "peer":
      currentInviteUrl = undefined;
      elements.chat.dataset.view = "chat";
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

function handlePeerDisconnected(): void {
  if (setConnectionState("disconnected")) {
    presentPeerDisconnected();
  }
}

function presentPeerDisconnected(): void {
  elements.emptyTitle.textContent = "Peer disconnected";
  elements.emptyDetail.textContent = "Create a new invite to start another private chat.";
  showNotice("Peer disconnected", "The direct connection closed.");
  elements.retryButton.hidden = false;
}

function setConnectionState(nextState: ConnectionState, label?: string): boolean {
  const view = connectionView(state, nextState);
  state = nextState;
  elements.statusDot.dataset.state = nextState;
  elements.statusText.textContent = label ?? view.label;
  elements.messageInput.disabled = !view.canSend;
  elements.sendButton.disabled = !view.canSend;
  elements.messageInput.placeholder = view.canSend ? "Write a message" : "Connect to send a message";
  return view.peerDisconnected;
}

function appendMessage(message: {
  direction: "incoming" | "outgoing";
  sender?: string;
  text: string;
  timestamp: number;
}): void {
  const shouldScroll = message.direction === "outgoing" || messagesAreNearEnd();
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
  if (shouldScroll) {
    requestAnimationFrame(() => scrollMessagesToEnd(true));
  }
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
  const maxHeight = Number.parseFloat(window.getComputedStyle(elements.messageInput).maxHeight) || 132;
  elements.messageInput.style.height = `${Math.min(elements.messageInput.scrollHeight, maxHeight)}px`;
  elements.messageInput.dataset.overflow = String(elements.messageInput.scrollHeight > maxHeight);
  if (document.activeElement === elements.messageInput) {
    requestAnimationFrame(() => scrollMessagesToEnd(false));
  }
}

function messagesAreNearEnd(): boolean {
  const remaining = elements.messages.scrollHeight - elements.messages.scrollTop - elements.messages.clientHeight;
  return remaining < 80;
}

function scrollMessagesToEnd(smooth: boolean): void {
  elements.messages.scrollTo({
    top: elements.messages.scrollHeight,
    behavior: smooth && !window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "smooth" : "auto",
  });
}

function installViewportSync(): void {
  const viewport = window.visualViewport;
  let frame = 0;
  const sync = (): void => {
    window.cancelAnimationFrame(frame);
    frame = window.requestAnimationFrame(() => {
      const height = viewport?.height ?? window.innerHeight;
      document.documentElement.style.setProperty("--app-height", `${Math.round(height)}px`);
      document.documentElement.style.setProperty("--app-top", `${Math.round(viewport?.offsetTop ?? 0)}px`);
      resizeComposer();
      if (document.activeElement === elements.messageInput) {
        scrollMessagesToEnd(false);
      }
    });
  };

  viewport?.addEventListener("resize", sync);
  viewport?.addEventListener("scroll", sync);
  window.addEventListener("resize", sync);
  sync();
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

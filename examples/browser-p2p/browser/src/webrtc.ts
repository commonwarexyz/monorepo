import type { BrowserP2pSession } from "./bridge";
import { AttachmentBarrier } from "./attachment-barrier";
import type { Invite } from "./invite";
import { RendezvousClient, rendezvousUrl, type ServerEvent } from "./rendezvous";
import { SignalingCipher, type Role, type Signal } from "./signaling";

const CHANNEL_LABEL = "commonware-p2p-v1";
const NEGOTIATION_TIMEOUT_MS = 45_000;

export class WebRtcPairing {
  readonly #role: Role;
  readonly #invite: Invite;
  readonly #chat: BrowserP2pSession;
  readonly #connection: RTCPeerConnection;
  readonly #rendezvous: RendezvousClient;
  readonly #cipher: SignalingCipher;
  readonly #onState: (state: string) => void;
  readonly #pendingCandidates: RTCIceCandidateInit[] = [];
  readonly #attachmentBarrier = new AttachmentBarrier();
  #channel?: RTCDataChannel;
  #expectedPeer?: string;
  #receiveChain = Promise.resolve();
  #sendChain = Promise.resolve();
  #attached = false;
  #prepared = false;
  #signalingClosed = false;
  #closed = false;
  #offEvent: () => void;
  #timeout: number;

  constructor(options: {
    role: Role;
    invite: Invite;
    chat: BrowserP2pSession;
    iceServers: RTCIceServer[];
    onState: (state: string) => void;
  }) {
    this.#role = options.role;
    this.#invite = options.invite;
    this.#chat = options.chat;
    this.#onState = options.onState;
    this.#connection = new RTCPeerConnection({ iceServers: options.iceServers });
    this.#cipher = new SignalingCipher(options.invite.session, options.invite.secret, options.role);
    this.#rendezvous = new RendezvousClient(
      rendezvousUrl(window.location),
      options.invite.session,
      options.role,
    );
    this.#offEvent = this.#rendezvous.onEvent((event) => this.#queueEvent(event));
    this.#timeout = window.setTimeout(
      () => this.#fail(new Error("WebRTC negotiation timed out.")),
      NEGOTIATION_TIMEOUT_MS,
    );

    this.#connection.addEventListener("icecandidate", (event) => {
      if (event.candidate && !this.#signalingClosed) {
        this.#send({ type: "candidate", candidate: event.candidate.toJSON() });
      }
    });
    this.#connection.addEventListener("connectionstatechange", () => {
      if (this.#connection.connectionState === "connected") {
        void this.#prepareAdapter();
        return;
      }
      if (["failed", "closed"].includes(this.#connection.connectionState)) {
        this.#fail(new Error("The direct WebRTC connection closed."));
      }
    });

    if (options.role === "initiator") {
      this.#channel = this.#connection.createDataChannel(CHANNEL_LABEL, {
        ordered: true,
        protocol: CHANNEL_LABEL,
      });
      this.#watchChannel(this.#channel);
    } else {
      this.#expectedPeer = options.invite.initiatorKey;
      this.#connection.addEventListener("datachannel", (event) => {
        if (this.#channel) {
          event.channel.close();
          this.#fail(new Error("The peer opened more than one data channel."));
          return;
        }
        try {
          validateChannel(event.channel);
          this.#channel = event.channel;
          this.#watchChannel(event.channel);
        } catch (error) {
          event.channel.close();
          this.#fail(error);
        }
      });
    }
  }

  async start(): Promise<void> {
    this.#onState(this.#role === "initiator" ? "Waiting for phone" : "Joining securely");
    await this.#rendezvous.ready();
    if (this.#role === "responder") {
      await this.#send({ type: "identity", publicKey: this.#chat.publicKey() });
    }
  }

  close(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    window.clearTimeout(this.#timeout);
    this.#offEvent();
    this.#rendezvous.close();
    this.#channel?.close();
    this.#connection.close();
  }

  #queueEvent(event: ServerEvent): void {
    if (event.type === "signal") {
      this.#receiveChain = this.#receiveChain
        .then(async () => this.#handleSignal(await this.#cipher.open(event.payload)))
        .catch((error: unknown) => this.#fail(error));
      return;
    }
    if (event.type === "error") {
      this.#fail(new Error(event.message));
    }
  }

  async #handleSignal(signal: Signal): Promise<void> {
    if (this.#closed) {
      return;
    }
    switch (signal.type) {
      case "identity":
        if (this.#role !== "initiator" || this.#expectedPeer) {
          throw new Error("The peer identity was unexpected.");
        }
        this.#expectedPeer = signal.publicKey;
        this.#onState("Phone found · connecting");
        await this.#connection.setLocalDescription(await this.#connection.createOffer());
        await this.#send({
          type: "description",
          description: descriptionInit(this.#connection.localDescription),
        });
        return;
      case "description":
        await this.#applyDescription(signal.description);
        return;
      case "candidate":
        if (!this.#connection.remoteDescription) {
          this.#pendingCandidates.push(signal.candidate);
          return;
        }
        await this.#connection.addIceCandidate(signal.candidate);
        return;
      case "adapter-ready":
        if (this.#attachmentBarrier.markRemoteReady()) {
          await this.#startAttachment();
        }
    }
  }

  async #applyDescription(description: RTCSessionDescriptionInit): Promise<void> {
    const expectedType = this.#role === "initiator" ? "answer" : "offer";
    if (description.type !== expectedType || this.#connection.remoteDescription) {
      throw new Error("The peer sent an unexpected session description.");
    }
    await this.#connection.setRemoteDescription(description);
    for (const candidate of this.#pendingCandidates.splice(0)) {
      await this.#connection.addIceCandidate(candidate);
    }

    if (this.#role === "responder") {
      await this.#connection.setLocalDescription(await this.#connection.createAnswer());
      await this.#send({
        type: "description",
        description: descriptionInit(this.#connection.localDescription),
      });
      this.#onState("Connecting directly");
    }
  }

  #send(signal: Signal): Promise<void> {
    if (this.#signalingClosed) {
      return Promise.resolve();
    }
    const operation = this.#sendChain.then(async () => {
      const envelope = await this.#cipher.seal(signal);
      this.#rendezvous.send(envelope);
    });
    this.#sendChain = operation.catch((error: unknown) => this.#fail(error));
    return operation;
  }

  #watchChannel(channel: RTCDataChannel): void {
    validateChannel(channel);
    channel.addEventListener("open", () => void this.#prepareAdapter());
    channel.addEventListener("error", () => this.#fail(new Error("The data channel failed.")));
    if (channel.readyState === "open") {
      void this.#prepareAdapter();
    }
  }

  async #prepareAdapter(): Promise<void> {
    if (
      this.#prepared ||
      this.#closed ||
      !this.#channel ||
      this.#channel.readyState !== "open" ||
      this.#connection.connectionState !== "connected" ||
      !this.#expectedPeer
    ) {
      return;
    }
    try {
      this.#chat.prepare(this.#connection, this.#channel);
      this.#prepared = true;
      const start = this.#attachmentBarrier.markLocalReady();
      await this.#send({ type: "adapter-ready" });
      if (start) {
        await this.#startAttachment();
      }
    } catch (error) {
      this.#fail(error);
    }
  }

  async #startAttachment(): Promise<void> {
    if (this.#attached || this.#closed || !this.#prepared || !this.#expectedPeer) {
      return;
    }
    this.#attached = true;
    this.#onState("Authenticating peer");
    try {
      await this.#chat.attach(
        this.#expectedPeer,
        this.#role === "responder",
      );
      this.#signalingClosed = true;
      window.clearTimeout(this.#timeout);
      this.#offEvent();
      this.#rendezvous.close();
      this.#onState("Connected directly");
    } catch (error) {
      this.#attached = false;
      this.#fail(error);
    }
  }

  #fail(error: unknown): void {
    if (this.#closed) {
      return;
    }
    this.close();
    window.dispatchEvent(new CustomEvent("commonware-pairing-error", { detail: error }));
  }
}

export interface WebRtcApplicationConfig {
  applicationUrl: string;
  iceServers: RTCIceServer[];
}

export async function loadWebRtcConfig(): Promise<WebRtcApplicationConfig> {
  const response = await fetch("/config.json", { cache: "no-store" });
  if (!response.ok) {
    throw new Error("Could not load the WebRTC configuration.");
  }
  const text = await response.text();
  if (text.length > 12_288) {
    throw new Error("The WebRTC configuration is too large.");
  }
  const value: unknown = JSON.parse(text);
  if (
    !isRecord(value) ||
    typeof value.applicationUrl !== "string" ||
    value.applicationUrl.length > 2048 ||
    !Array.isArray(value.iceServers) ||
    value.iceServers.length > 8
  ) {
    throw new Error("The WebRTC configuration is invalid.");
  }

  const applicationUrl = new URL(value.applicationUrl);
  if (
    (applicationUrl.protocol !== "http:" && applicationUrl.protocol !== "https:") ||
    applicationUrl.username ||
    applicationUrl.password ||
    applicationUrl.search ||
    applicationUrl.hash
  ) {
    throw new Error("The application URL is invalid.");
  }

  return {
    applicationUrl: applicationUrl.toString(),
    iceServers: value.iceServers as RTCIceServer[],
  };
}

function validateChannel(channel: RTCDataChannel): void {
  if (
    channel.label !== CHANNEL_LABEL ||
    channel.protocol !== CHANNEL_LABEL ||
    !channel.ordered ||
    channel.maxPacketLifeTime !== null ||
    channel.maxRetransmits !== null
  ) {
    throw new Error("The peer offered an incompatible data channel.");
  }
}

function descriptionInit(description: RTCSessionDescription | null): RTCSessionDescriptionInit {
  if (!description?.sdp) {
    throw new Error("The browser did not create a session description.");
  }
  return { type: description.type, sdp: description.sdp };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

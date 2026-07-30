import type { ConnectionState } from "./bridge";

export interface ConnectionView {
  canSend: boolean;
  label: string;
  peerDisconnected: boolean;
}

export function connectionView(
  previous: ConnectionState,
  current: ConnectionState,
): ConnectionView {
  return {
    canSend: current === "connected",
    label: connectionLabel(current),
    peerDisconnected: previous === "connected" && current === "disconnected",
  };
}

function connectionLabel(state: ConnectionState): string {
  switch (state) {
    case "connecting": return "Connecting";
    case "connected": return "Connected directly";
    case "reconnecting": return "Reconnecting";
    case "disconnected": return "Disconnected";
  }
}

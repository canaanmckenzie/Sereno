export type AuthStatus = "allow" | "deny" | "ask" | "auto";
export type Direction = "inbound" | "outbound";
export type Protocol = "tcp" | "udp" | "icmp";
export type SignatureStatus = "signed" | "unsigned" | "invalid" | "system" | "unknown";

export interface Connection {
  id: string;
  time: string;
  authStatus: AuthStatus;
  direction: Direction;
  signatureStatus: SignatureStatus;
  processName: string;
  processId: number;
  processPath?: string;
  destination: string;
  remoteAddress: string;
  remotePort: number;
  localPort?: number;
  protocol: Protocol;
  bytesSent: number;
  bytesReceived: number;
  isActive: boolean;
  firstSeen?: string;
}

export interface GroupedConnection {
  processName: string;
  destination: string;
  pidCount: number;
  connectionCount: number;
  protocols: Protocol[];
  ports: number[];
  totalBytesSent: number;
  totalBytesReceived: number;
  authStatus: AuthStatus;
  isAnyActive: boolean;
  firstSeen: string;
}

export interface ConnectionFilters {
  hideLocalhost: boolean;
  hideSystem: boolean;
  hideInactive: boolean;
  hideZeroAddr: boolean;
  searchQuery: string;
}

export interface Box { nonce: string; ciphertext: string }
export interface Item { id: string; label: string; version: number; data: Box; wrappedKey: Box; createdAt: string }
export interface Approval {
  id: string; itemId: string; itemVersion: number; label: string; agent: string;
  operation: string; destination: string; leaseSeconds: number; keyId: string;
  status: 'pending' | 'approved' | 'denied' | 'completed'; createdAt: string; expiresAt: string;
}
export interface Grant { id: string; approvalId: string; itemId: string; label: string; approvedAt: string; expiresAt: string; revokedAt: string | null; uses: number; active: boolean }
export interface Event { id: string; kind: string; detail: string; at: string }
export interface Message { id: string; role: 'user' | 'assistant'; text: string; approvalId?: string; at: string }
export interface State {
  id: string; name: string; prfSalt: string; vaultKey: Box | null; recoveryKey: Box | null;
  items: Item[] | null; approvals: Approval[] | null; grants: Grant[]; events: Event[] | null; messages: Message[] | null;
}
export interface Ceremony { token: string; publicKey: Record<string, unknown>; salt: string }
export interface ApprovalDetail { request: Approval; publicKey: string; keyId: string }

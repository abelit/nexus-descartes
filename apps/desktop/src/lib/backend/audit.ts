import { apiUrl } from "@/lib/common/webPath";
import { backendResponseError } from "./http";

/**
 * Audit API client.
 *
 * Phase A protects `/api/audit/*` with a bootstrap token (or loopback-only
 * access when no token is configured), because every Web session is still the
 * same bootstrap administrator. The token is entered by the user and kept in
 * `sessionStorage` only.
 */
const TOKEN_STORAGE_KEY = "dbx.audit.accessToken";

export function auditAccessToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setAuditAccessToken(token: string): void {
  try {
    if (token.trim()) sessionStorage.setItem(TOKEN_STORAGE_KEY, token.trim());
    else sessionStorage.removeItem(TOKEN_STORAGE_KEY);
  } catch {
    // Storage can be unavailable (private mode); the in-memory token still works.
  }
}

function auditHeaders(extra?: Record<string, string>): Record<string, string> {
  const token = auditAccessToken();
  return token ? { "X-DBX-Audit-Token": token, ...extra } : { ...extra };
}

export interface AuditActor {
  id: string;
  display_name: string;
  kind: string;
  roles: string[];
  tenant_id?: string | null;
  session_id?: string | null;
  auth_method: string;
}

export interface AuditEvent {
  seq: number;
  event_id: string;
  occurred_at: string;
  event_type: string;
  actor: AuditActor;
  source: string;
  client_ip?: string | null;
  user_agent?: string | null;
  request_id?: string | null;
  request_method?: string | null;
  request_path?: string | null;
  http_status?: number | null;
  connection_id?: string | null;
  connection_name?: string | null;
  database?: string | null;
  schema_name?: string | null;
  table_name?: string | null;
  resource_type?: string | null;
  resource_id?: string | null;
  operation: string;
  sql_text?: string | null;
  sql_digest?: string | null;
  sql_fingerprint?: string | null;
  risk_level?: string | null;
  decision: string;
  rule_id?: string | null;
  matched_rule_ids?: string[];
  policy_version?: number | null;
  policy_bundle_hash?: string | null;
  approval_id?: string | null;
  outcome: string;
  error_code?: string | null;
  error_message?: string | null;
  affected_rows?: number | null;
  duration_ms?: number | null;
  details_json?: string | null;
  execution_id?: string | null;
  statement_index?: number | null;
  redaction_mode?: string | null;
  actor_verified: boolean;
  on_behalf_of?: string | null;
  delegated_by?: string | null;
  prev_hash: string;
  event_hash: string;
}

export interface AuditPage {
  events: AuditEvent[];
  next_cursor?: number | null;
}

export interface AuditCount {
  key: string;
  count: number;
}

export interface AuditStats {
  total: number;
  by_decision: AuditCount[];
  by_operation: AuditCount[];
  by_actor: AuditCount[];
  by_risk: AuditCount[];
}

export interface AuditChainReport {
  checked: number;
  first_broken_seq?: number | null;
  head_seq: number;
  head_hash: string;
}

export interface AuditChainHead {
  chain_id: string;
  last_seq: number;
  last_hash: string;
  event_count: number;
}

export interface AuditCheckpoint {
  seq: number;
  event_hash: string;
  signed_at: string;
  signature?: string | null;
  exported_at?: string | null;
}

export interface AuditCheckpointReport {
  checkpoint?: AuditCheckpoint | null;
  report: AuditChainReport;
}

export interface AuditQueryParams {
  actor_id?: string;
  connection_id?: string;
  database?: string;
  operation?: string;
  decision?: string;
  outcome?: string;
  sql_contains?: string;
  from_ms?: number;
  to_ms?: number;
  cursor_seq?: number;
  limit?: number;
}

function auditQueryString(params: AuditQueryParams): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  return search.toString();
}

export async function listAuditEvents(params: AuditQueryParams = {}): Promise<AuditPage> {
  const query = auditQueryString(params);
  const response = await fetch(apiUrl(`/api/audit/events${query ? `?${query}` : ""}`), {
    headers: auditHeaders(),
  });
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<AuditPage>;
}

export async function getAuditEvent(eventId: string): Promise<AuditEvent> {
  const response = await fetch(apiUrl(`/api/audit/events/${encodeURIComponent(eventId)}`), {
    headers: auditHeaders(),
  });
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<AuditEvent>;
}

export async function getAuditStats(params: Pick<AuditQueryParams, "from_ms" | "to_ms"> = {}): Promise<AuditStats> {
  const query = auditQueryString(params);
  const response = await fetch(apiUrl(`/api/audit/stats${query ? `?${query}` : ""}`), {
    headers: auditHeaders(),
  });
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<AuditStats>;
}

export async function getAuditChainHead(): Promise<AuditChainHead> {
  const response = await fetch(apiUrl("/api/audit/chain-head"), { headers: auditHeaders() });
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<AuditChainHead>;
}

export async function verifyAuditChain(): Promise<AuditChainReport> {
  const response = await fetch(apiUrl("/api/audit/verify"), { headers: auditHeaders() });
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<AuditChainReport>;
}

export async function verifyAuditChainFromCheckpoint(): Promise<AuditCheckpointReport> {
  const response = await fetch(apiUrl("/api/audit/verify-checkpoint"), { headers: auditHeaders() });
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<AuditCheckpointReport>;
}

export async function listAuditCheckpoints(): Promise<AuditCheckpoint[]> {
  const response = await fetch(apiUrl("/api/audit/checkpoints"), { headers: auditHeaders() });
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<AuditCheckpoint[]>;
}

export async function createAuditCheckpoint(): Promise<AuditCheckpoint> {
  const response = await fetch(apiUrl("/api/audit/checkpoints"), {
    method: "POST",
    headers: auditHeaders(),
  });
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<AuditCheckpoint>;
}

export async function downloadAuditExport(format: "jsonl" | "csv", params: AuditQueryParams = {}): Promise<Blob> {
  const query = auditQueryString(params);
  const suffix = query ? `?format=${format}&${query}` : `?format=${format}`;
  const response = await fetch(apiUrl(`/api/audit/export${suffix}`), { headers: auditHeaders() });
  if (!response.ok) throw await backendResponseError(response);
  return response.blob();
}

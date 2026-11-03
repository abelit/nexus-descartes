import { apiUrl } from "@/lib/common/webPath";
import { backendResponseError } from "./http";

export interface ApprovalStep {
  id: string;
  step_no: number;
  mode: string;
  status: string;
  approver_roles: string[];
  approver_users: string[];
  required_user_ids: string[];
  decided_by?: string | null;
  decided_at_ms?: number | null;
  comment: string;
}

export interface ApprovalDecision {
  step_no: number;
  actor_id: string;
  decision: string;
  comment: string;
  created_at_ms: number;
}

export interface ApprovalRequest {
  id: string;
  request_type: string;
  status: string;
  requester_id: string;
  connection_id: string;
  database: string;
  schema_name?: string | null;
  sql_text: string;
  statement_count: number;
  risk_level?: string | null;
  rule_ids: string[];
  justification: string;
  template_id: string;
  current_step_no: number;
  step_count: number;
  execution_mode: string;
  execution_error?: string | null;
  executed_by?: string | null;
  executed_at_ms?: number | null;
  steps: ApprovalStep[];
  created_at_ms: number;
  expires_at_ms?: number | null;
}

export interface ApprovalDetail extends ApprovalRequest {
  decisions: ApprovalDecision[];
}

export interface ExecuteToken {
  token: string;
  expires_at_ms: number;
}

export interface ApprovalTemplate {
  id: string;
  name: string;
  scope_type: string;
  scope_id: string;
  steps: Array<{ mode: string; roles: string[]; users: string[] }>;
  sla_secs?: number | null;
  enabled: boolean;
  created_by: string;
  created_at_ms: number;
  updated_at_ms: number;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), init);
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<T>;
}

export function listApprovals(params: { mine?: boolean; status?: string; assigned?: boolean } = {}): Promise<ApprovalRequest[]> {
  const search = new URLSearchParams();
  if (params.mine) search.set("mine", "true");
  if (params.status) search.set("status", params.status);
  if (params.assigned) search.set("assigned", "true");
  const suffix = search.toString() ? `?${search.toString()}` : "";
  return request<ApprovalRequest[]>(`/api/approvals${suffix}`);
}

export function getApproval(id: string): Promise<ApprovalDetail> {
  return request<ApprovalDetail>(`/api/approvals/${encodeURIComponent(id)}`);
}

export function createApproval(input: { connection_id: string; database: string; schema_name?: string; sql: string; justification?: string; template_id?: string; execution_mode?: "submitter" | "last_approver" | "auto" }): Promise<ApprovalRequest> {
  return request<ApprovalRequest>("/api/approvals", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function decideApproval(id: string, decision: "approve" | "reject", comment = ""): Promise<ApprovalRequest> {
  return request<ApprovalRequest>(`/api/approvals/${encodeURIComponent(id)}/${decision}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ comment }),
  });
}

export function issueExecuteToken(id: string): Promise<ExecuteToken> {
  return request<ExecuteToken>(`/api/approvals/${encodeURIComponent(id)}/execute-token`, { method: "POST" });
}

/// Executes the statements stored on an approved request (DMS-style). The
/// client does not send SQL; the server runs the reviewed artifact once.
export function executeApproval(id: string): Promise<ApprovalRequest> {
  return request<ApprovalRequest>(`/api/approvals/${encodeURIComponent(id)}/execute`, { method: "POST" });
}

export function listApprovalTemplates(): Promise<ApprovalTemplate[]> {
  return request<ApprovalTemplate[]>("/api/approval-templates");
}

export function createApprovalTemplate(input: { name: string; scope_type: string; scope_id: string; steps: unknown; enabled?: boolean }): Promise<ApprovalTemplate> {
  return request<ApprovalTemplate>("/api/approval-templates", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function updateApprovalTemplate(id: string, input: { name: string; scope_type: string; scope_id: string; steps: unknown; enabled?: boolean }): Promise<ApprovalTemplate> {
  return request<ApprovalTemplate>(`/api/approval-templates/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function deleteApprovalTemplate(id: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/approval-templates/${encodeURIComponent(id)}`, { method: "DELETE" });
}

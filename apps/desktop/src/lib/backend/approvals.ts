import { apiUrl } from "@/lib/common/webPath";
import { backendResponseError } from "./http";

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
  created_at_ms: number;
  expires_at_ms?: number | null;
}

export interface ExecuteToken {
  token: string;
  expires_at_ms: number;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), init);
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<T>;
}

export function listApprovals(params: { mine?: boolean; status?: string } = {}): Promise<ApprovalRequest[]> {
  const search = new URLSearchParams();
  if (params.mine) search.set("mine", "true");
  if (params.status) search.set("status", params.status);
  const suffix = search.toString() ? `?${search.toString()}` : "";
  return request<ApprovalRequest[]>(`/api/approvals${suffix}`);
}

export function createApproval(input: { connection_id: string; database: string; sql: string; justification?: string }): Promise<ApprovalRequest> {
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

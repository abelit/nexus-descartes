import { apiUrl } from "@/lib/common/webPath";
import { backendResponseError } from "./http";

export interface MyTaskApproval {
  id: string;
  sql: string;
  requester_id: string;
  requester_name: string;
  connection_id: string;
  connection_name?: string | null;
  database: string;
  schema_name?: string | null;
  status: "pending" | "approved" | "executing" | "executed" | "execution_failed" | "rejected" | "expired" | "cancelled";
  step_count: number;
  current_step_no: number;
  current_approver_names: string[];
  execution_mode: string;
  execution_error?: string | null;
  created_at_ms: number;
  updated_at_ms: number;
  executed_at_ms?: number | null;
  expires_at_ms?: number | null;
}

export interface MyTaskAccessRequest {
  id: string;
  requester_id: string;
  requester_name: string;
  role_code: string;
  role_name: string;
  target_kind: "connection_group" | "connection" | "database" | "schema" | "table";
  connection_group_id?: string | null;
  connection_id?: string | null;
  connection_name?: string | null;
  group_name?: string | null;
  database_name?: string | null;
  schema_name?: string | null;
  table_name?: string | null;
  name_pattern: boolean;
  status: "pending" | "approved" | "rejected" | "cancelled";
  current_approver_names: string[];
  duration_hours: number;
  expires_at: string;
  created_at: string;
  updated_at: string;
  decided_at?: string | null;
  decision_note: string;
  decided_by_name?: string | null;
  grant_id?: string | null;
  expired: boolean;
}

export interface MyTasksResponse {
  approvals: MyTaskApproval[];
  access_requests: MyTaskAccessRequest[];
  pending_approvals: MyTaskApproval[];
  pending_access_requests: MyTaskAccessRequest[];
  generated_at_ms: number;
}

export async function listMyTasks(limit = 20): Promise<MyTasksResponse> {
  const response = await fetch(apiUrl(`/api/my-tasks?limit=${limit}`));
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<MyTasksResponse>;
}

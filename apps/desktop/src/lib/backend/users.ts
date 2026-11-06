import { apiUrl } from "@/lib/common/webPath";
import { backendResponseError } from "./http";

export interface LocalUser {
  id: string;
  email: string;
  display_name: string;
  status: string;
  is_builtin: boolean;
  created_at: string;
  last_login_at?: string | null;
  roles: string[];
  asset_roles?: string[];
  permissions: string[];
  effective_permissions?: string[];
  bindings?: UserBinding[];
}

export interface LocalRole {
  code: string;
  name: string;
  description: string;
  permissions: string[];
  builtin?: boolean;
}

export interface UserSession {
  id: string;
  created_at_ms: number;
  last_seen_at_ms: number;
  expires_at_ms: number;
  client_ip?: string | null;
  user_agent?: string | null;
}

export interface RoleInput {
  code?: string;
  name: string;
  description?: string;
  permissions: string[];
}

export interface RoleScope {
  scope_type: "global" | "connection" | "connection_group" | "database" | "schema" | "table";
  scope_id?: string | null;
}

export interface AssetGrant {
  id: string;
  principal_type?: "user" | "group";
  principal_id?: string;
  role_code: string;
  target_kind: "connection_group" | "connection" | "database" | "schema" | "table";
  connection_group_id?: string | null;
  connection_id?: string | null;
  database_name?: string | null;
  schema_name?: string | null;
  table_name?: string | null;
  name_pattern: boolean;
  expires_at?: string | null;
  granted_by?: string | null;
  reason: string;
  created_at: string;
}

export interface CreateAssetGrantInput {
  role_code: string;
  target_kind: AssetGrant["target_kind"];
  connection_group_id?: string | null;
  connection_id?: string | null;
  database_name?: string | null;
  schema_name?: string | null;
  table_name?: string | null;
  name_pattern?: boolean;
  expires_at?: string | null;
  reason?: string;
}

export interface UserBinding {
  role_code: string;
  scope_type: string;
  scope_id?: string | null;
}

export interface ConnectionGroup {
  id: string;
  name: string;
  parent_id?: string | null;
  connection_ids: string[];
}

export interface CreateUserInput {
  email: string;
  display_name: string;
  password: string;
  role: string;
  scope?: RoleScope;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), init);
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<T>;
}

export function listUsers(): Promise<LocalUser[]> {
  return request<LocalUser[]>("/api/users");
}

export function listRoles(): Promise<LocalRole[]> {
  return request<LocalRole[]>("/api/roles");
}

export function createUser(input: CreateUserInput): Promise<LocalUser> {
  return request<LocalUser>("/api/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function updateUser(userId: string, patch: { status?: string; role?: string; display_name?: string; scope?: RoleScope; clear_global_role?: boolean }): Promise<LocalUser> {
  return request<LocalUser>(`/api/users/${encodeURIComponent(userId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(patch),
  });
}

export function revokeUserSessions(userId: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/users/${encodeURIComponent(userId)}/sessions/revoke`, {
    method: "POST",
  });
}

export function listUserSessions(userId: string): Promise<UserSession[]> {
  return request<UserSession[]>(`/api/users/${encodeURIComponent(userId)}/sessions`);
}

export function revokeUserSession(userId: string, sessionId: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/users/${encodeURIComponent(userId)}/sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE" });
}

export function resetUserPassword(userId: string, password: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/users/${encodeURIComponent(userId)}/password`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
}

export function createRole(input: RoleInput & { code: string }): Promise<LocalRole> {
  return request<LocalRole>("/api/roles", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function updateRole(code: string, input: RoleInput): Promise<LocalRole> {
  return request<LocalRole>(`/api/roles/${encodeURIComponent(code)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function deleteRole(code: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/roles/${encodeURIComponent(code)}`, { method: "DELETE" });
}

export function listConnectionGroups(): Promise<ConnectionGroup[]> {
  return request<ConnectionGroup[]>("/api/connection-groups");
}

export function createConnectionGroup(name: string, parentId?: string | null): Promise<ConnectionGroup> {
  return request<ConnectionGroup>("/api/connection-groups", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, parent_id: parentId || null }),
  });
}

export function deleteConnectionGroup(groupId: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/connection-groups/${encodeURIComponent(groupId)}`, { method: "DELETE" });
}

export function setConnectionGroupMembers(groupId: string, connectionIds: string[]): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/connection-groups/${encodeURIComponent(groupId)}/members`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ connection_ids: connectionIds }),
  });
}

export function listAssetGrants(userId: string): Promise<AssetGrant[]> {
  return request<AssetGrant[]>(`/api/users/${encodeURIComponent(userId)}/bindings`);
}

export function createAssetGrant(userId: string, input: CreateAssetGrantInput): Promise<AssetGrant> {
  return request<AssetGrant>(`/api/users/${encodeURIComponent(userId)}/bindings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function deleteAssetGrant(userId: string, grantId: string): Promise<RevokeGrantResult> {
  return request<RevokeGrantResult>(`/api/users/${encodeURIComponent(userId)}/bindings/${encodeURIComponent(grantId)}`, { method: "DELETE" });
}

/** What the user will still be able to do after this grant is removed. */
export interface GrantCoverage {
  grant_id: string;
  still_covered: boolean;
  missing_permissions: string[];
  via_global_roles: boolean;
  remaining_grants: AssetGrant[];
  access_request_ids: string[];
}

export interface RevokeGrantResult {
  ok: boolean;
  coverage: GrantCoverage;
  revoked_access_request_ids: string[];
}

export function getGrantCoverage(userId: string, grantId: string): Promise<GrantCoverage> {
  return request<GrantCoverage>(`/api/users/${encodeURIComponent(userId)}/bindings/${encodeURIComponent(grantId)}/coverage`);
}

export interface UpdateAssetGrantInput {
  role_code?: string;
  /** `null` clears the expiry; omit the field to leave it unchanged. */
  expires_at?: string | null;
  reason?: string;
}

export function updateAssetGrant(userId: string, grantId: string, input: UpdateAssetGrantInput): Promise<AssetGrant> {
  return request<AssetGrant>(`/api/users/${encodeURIComponent(userId)}/bindings/${encodeURIComponent(grantId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export interface AssetGroup {
  id: string;
  name: string;
  description: string;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
  member_count: number;
  grant_count: number;
}

export interface AssetGroupMember {
  user_id: string;
  email: string;
  display_name: string;
  status: string;
  added_by?: string | null;
  created_at: string;
}

export interface AssetGroupDetail {
  group: AssetGroup;
  members: AssetGroupMember[];
  grants: AssetGrant[];
}

export interface AssetGroupInput {
  name: string;
  description?: string;
}

export function listAssetGroups(): Promise<AssetGroup[]> {
  return request<AssetGroup[]>("/api/asset-groups");
}

export function createAssetGroup(input: AssetGroupInput): Promise<AssetGroup> {
  return request<AssetGroup>("/api/asset-groups", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function updateAssetGroup(groupId: string, input: AssetGroupInput): Promise<AssetGroup> {
  return request<AssetGroup>(`/api/asset-groups/${encodeURIComponent(groupId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function deleteAssetGroup(groupId: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/asset-groups/${encodeURIComponent(groupId)}`, { method: "DELETE" });
}

export function getAssetGroup(groupId: string): Promise<AssetGroupDetail> {
  return request<AssetGroupDetail>(`/api/asset-groups/${encodeURIComponent(groupId)}`);
}

export function addAssetGroupMember(groupId: string, userId: string): Promise<{ ok: boolean; added: boolean }> {
  return request<{ ok: boolean; added: boolean }>(`/api/asset-groups/${encodeURIComponent(groupId)}/members`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: userId }),
  });
}

export function removeAssetGroupMember(groupId: string, userId: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/asset-groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`, { method: "DELETE" });
}

export function createGroupAssetGrant(groupId: string, input: CreateAssetGrantInput): Promise<AssetGrant> {
  return request<AssetGrant>(`/api/asset-groups/${encodeURIComponent(groupId)}/bindings`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function updateGroupAssetGrant(groupId: string, grantId: string, input: UpdateAssetGrantInput): Promise<AssetGrant> {
  return request<AssetGrant>(`/api/asset-groups/${encodeURIComponent(groupId)}/bindings/${encodeURIComponent(grantId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function deleteGroupAssetGrant(groupId: string, grantId: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/asset-groups/${encodeURIComponent(groupId)}/bindings/${encodeURIComponent(grantId)}`, { method: "DELETE" });
}

export interface EffectivePermission {
  permission: string;
  allowed: boolean;
  broad: boolean;
  grant_ids: string[];
  source: "global" | "grant" | "none";
  asset_scopeable: boolean;
}

export interface EffectiveAccess {
  user_id: string;
  connection_id: string;
  database?: string | null;
  schema?: string | null;
  table?: string | null;
  global_roles: string[];
  asset_roles: string[];
  permissions: EffectivePermission[];
  can_navigate_connection: boolean;
  can_navigate_database: boolean;
  can_navigate_schema: boolean;
}

export function effectiveAccess(userId: string, query: { connection_id: string; database?: string; schema?: string; table?: string }): Promise<EffectiveAccess> {
  const params = new URLSearchParams();
  params.set("connection_id", query.connection_id);
  if (query.database?.trim()) params.set("database", query.database.trim());
  if (query.schema?.trim()) params.set("schema", query.schema.trim());
  if (query.table?.trim()) params.set("table", query.table.trim());
  return request<EffectiveAccess>(`/api/users/${encodeURIComponent(userId)}/effective-access?${params.toString()}`);
}

export interface AssetGrantInventoryItem {
  id: string;
  principal_type: "user" | "group";
  principal_id: string;
  principal_name: string;
  member_count: number;
  user_id: string;
  user_email: string;
  user_display_name: string;
  user_status: string;
  role_code: string;
  role_name: string;
  target_kind: AssetGrant["target_kind"];
  connection_group_id?: string | null;
  connection_id?: string | null;
  database_name?: string | null;
  schema_name?: string | null;
  table_name?: string | null;
  name_pattern: boolean;
  expires_at?: string | null;
  granted_by?: string | null;
  reason: string;
  created_at: string;
  connection_name?: string | null;
  group_name?: string | null;
  expired: boolean;
  stale_reason?: string | null;
}

export interface AssetGrantInventoryQuery {
  user_id?: string;
  connection_id?: string;
  database?: string;
  schema?: string;
  table?: string;
  role_code?: string;
  stale?: boolean;
}

export function listAssetGrantInventory(query: AssetGrantInventoryQuery = {}): Promise<AssetGrantInventoryItem[]> {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined || value === null || value === "") continue;
    params.set(key, String(value));
  }
  const suffix = params.toString();
  return request<AssetGrantInventoryItem[]>(`/api/asset-grants${suffix ? `?${suffix}` : ""}`);
}

export type AccessRequestStatus = "pending" | "approved" | "rejected" | "cancelled" | "revoked";

export type AccessGrantStatus = "active" | "expired" | "revoked" | "missing";

export interface AccessRequest {
  id: string;
  requester_id: string;
  requester_name: string;
  requester_email: string;
  role_code: string;
  role_name: string;
  target_kind: AssetGrant["target_kind"];
  connection_group_id?: string | null;
  connection_id?: string | null;
  connection_name?: string | null;
  group_name?: string | null;
  database_name?: string | null;
  schema_name?: string | null;
  table_name?: string | null;
  name_pattern: boolean;
  duration_hours: number;
  expires_at: string;
  justification: string;
  status: AccessRequestStatus;
  decided_by?: string | null;
  decided_by_name?: string | null;
  decided_at?: string | null;
  decision_note: string;
  grant_id?: string | null;
  grant_status?: AccessGrantStatus | null;
  approver_names: string[];
  created_at: string;
  expired: boolean;
}

export interface AccessRequestInput {
  role_code: string;
  target_kind: AssetGrant["target_kind"];
  connection_group_id?: string | null;
  connection_id?: string | null;
  database_name?: string | null;
  schema_name?: string | null;
  table_name?: string | null;
  name_pattern?: boolean;
  duration_hours: number;
  justification: string;
  /** Submit again after ACCESS_ALREADY_GRANTED to stack a new time window. */
  force?: boolean;
}

export interface AccessRequestRoleOption {
  code: string;
  name: string;
  permissions: string[];
}

export interface AccessRequestConnectionOption {
  id: string;
  name: string;
  db_type: string;
}

export interface AccessRequestGroupOption {
  id: string;
  name: string;
}

export interface AccessRequestOptions {
  roles: AccessRequestRoleOption[];
  connections: AccessRequestConnectionOption[];
  connection_groups: AccessRequestGroupOption[];
  max_duration_hours: number;
}

export function accessRequestOptions(): Promise<AccessRequestOptions> {
  return request<AccessRequestOptions>("/api/access-requests/options");
}

export function listAccessRequests(query: { scope?: "mine" | "all"; status?: AccessRequestStatus; limit?: number } = {}): Promise<AccessRequest[]> {
  const params = new URLSearchParams();
  if (query.scope) params.set("scope", query.scope);
  if (query.status) params.set("status", query.status);
  if (query.limit) params.set("limit", String(query.limit));
  const suffix = params.toString();
  return request<AccessRequest[]>(`/api/access-requests${suffix ? `?${suffix}` : ""}`);
}

export function createAccessRequest(input: AccessRequestInput): Promise<AccessRequest> {
  return request<AccessRequest>("/api/access-requests", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function cancelAccessRequest(requestId: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/access-requests/${encodeURIComponent(requestId)}/cancel`, {
    method: "POST",
  });
}

export function approveAccessRequest(requestId: string, note = ""): Promise<AccessRequest> {
  return request<AccessRequest>(`/api/access-requests/${encodeURIComponent(requestId)}/approve`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ note }),
  });
}

export function rejectAccessRequest(requestId: string, note = ""): Promise<AccessRequest> {
  return request<AccessRequest>(`/api/access-requests/${encodeURIComponent(requestId)}/reject`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ note }),
  });
}

export type DataPolicyKind = "mask" | "row_filter";

export interface DataPolicy {
  id: string;
  name: string;
  kind: DataPolicyKind;
  connection_id: string;
  database_name?: string | null;
  schema_name?: string | null;
  table_name: string;
  name_pattern: boolean;
  column_name: string;
  mask_type: "full" | "partial" | "email";
  replacement: string;
  allowed_values: string[];
  enabled: boolean;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
}

export interface DataPolicyInput {
  name: string;
  kind: DataPolicyKind;
  connection_id: string;
  database_name?: string | null;
  schema_name?: string | null;
  table_name: string;
  name_pattern?: boolean;
  column_name: string;
  mask_type?: string;
  replacement?: string;
  allowed_values?: string[];
  enabled?: boolean;
}

export function listDataPolicies(connectionId?: string): Promise<DataPolicy[]> {
  const suffix = connectionId ? `?connection_id=${encodeURIComponent(connectionId)}` : "";
  return request<DataPolicy[]>(`/api/data-policies${suffix}`);
}

export function createDataPolicy(input: DataPolicyInput): Promise<DataPolicy> {
  return request<DataPolicy>("/api/data-policies", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function updateDataPolicy(policyId: string, input: DataPolicyInput): Promise<DataPolicy> {
  return request<DataPolicy>(`/api/data-policies/${encodeURIComponent(policyId)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function deleteDataPolicy(policyId: string): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`/api/data-policies/${encodeURIComponent(policyId)}`, { method: "DELETE" });
}

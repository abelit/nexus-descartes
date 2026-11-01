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
  permissions: string[];
}

export interface LocalRole {
  code: string;
  name: string;
  description: string;
  permissions: string[];
}

export interface CreateUserInput {
  email: string;
  display_name: string;
  password: string;
  role: string;
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

export function updateUser(userId: string, patch: { status?: string; role?: string }): Promise<LocalUser> {
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

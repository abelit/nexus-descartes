import { apiUrl } from "@/lib/common/webPath";
import { backendResponseError } from "./http";

export interface PolicyVersion {
  id: string;
  scope_type: string;
  scope_id: string;
  version: number;
  created_by?: string | null;
  created_at_ms: number;
  note: string;
  document: unknown;
}

export interface EffectiveRule {
  id: string;
  enabled: boolean;
  priority: number;
  effect: string;
  scope: unknown;
  match: unknown;
  message: string;
  builtin: boolean;
}

export interface EffectivePolicy {
  policy_bundle_hash: string;
  rules: EffectiveRule[];
  documents: Array<{ scope: unknown; version: number; rules: number }>;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), init);
  if (!response.ok) throw await backendResponseError(response);
  return response.json() as Promise<T>;
}

export function listPolicies(scopeType: string, scopeId: string): Promise<PolicyVersion[]> {
  const search = new URLSearchParams({ scope_type: scopeType });
  if (scopeId) search.set("scope_id", scopeId);
  return request<PolicyVersion[]>(`/api/policies?${search.toString()}`);
}

export function publishPolicy(input: { scope_type: string; scope_id: string; document: unknown; note?: string }): Promise<PolicyVersion> {
  return request<PolicyVersion>("/api/policies", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function rollbackPolicy(input: { scope_type: string; scope_id: string; version: number; note?: string }): Promise<{ version: number }> {
  return request<{ version: number }>("/api/policies/rollback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
}

export function effectivePolicy(): Promise<EffectivePolicy> {
  return request<EffectivePolicy>("/api/policies/effective");
}

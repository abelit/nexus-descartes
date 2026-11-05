import { apiUrl } from "@/lib/common/webPath";
import { backendResponseError } from "./http";

export type PolicyEffect = "allow" | "warn" | "require_approval" | "block";

export interface PolicyRuleMatch {
  statement_types?: string[];
  production_only?: boolean;
  requires_where?: boolean | null;
  unbounded_only?: boolean;
  databases?: string[];
  tables?: string[];
}

export interface PolicyRule {
  id: string;
  enabled?: boolean;
  priority?: number;
  action: PolicyEffect;
  message: string;
  approval_template_id?: string | null;
  match?: PolicyRuleMatch;
}

export interface PolicyDocument {
  rules: PolicyRule[];
}

export interface PolicyVersion {
  id: string;
  scope_type: string;
  scope_id: string;
  version: number;
  created_by?: string | null;
  created_at_ms: number;
  note: string;
  document: PolicyDocument;
}

export interface EffectiveRule {
  id: string;
  enabled: boolean;
  priority: number;
  effect: string;
  scope: unknown;
  match: PolicyRuleMatch;
  message: string;
  approval_template_id?: string | null;
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

export function publishPolicy(input: { scope_type: string; scope_id: string; document: PolicyDocument; note?: string }): Promise<PolicyVersion> {
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

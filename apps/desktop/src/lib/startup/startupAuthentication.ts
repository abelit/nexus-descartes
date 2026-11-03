import { apiUrl } from "@/lib/common/webPath";

export interface AuthActor {
  id: string;
  display_name: string;
  roles: string[];
  asset_roles: string[];
  permissions: string[];
}

export interface StartupAuthentication {
  required: boolean;
  authenticated: boolean;
  setup_required: boolean;
  actor?: AuthActor | null;
}

function parseAuthActor(value: unknown): AuthActor | null {
  if (!value || typeof value !== "object") return null;
  const actor = value as Partial<AuthActor>;
  if (typeof actor.id !== "string" || !Array.isArray(actor.permissions)) return null;
  return {
    id: actor.id,
    display_name: typeof actor.display_name === "string" ? actor.display_name : actor.id,
    roles: Array.isArray(actor.roles) ? actor.roles.filter((role): role is string => typeof role === "string") : [],
    asset_roles: Array.isArray(actor.asset_roles) ? actor.asset_roles.filter((role): role is string => typeof role === "string") : [],
    permissions: actor.permissions.filter((permission): permission is string => typeof permission === "string"),
  };
}

export async function checkStartupAuthentication(signal?: AbortSignal): Promise<StartupAuthentication> {
  const response = await fetch(apiUrl("/api/auth/check"), { credentials: "same-origin", signal });
  if (!response.ok) throw new Error("AUTH_CHECK_FAILED");
  const result: unknown = await response.json();
  if (!result || typeof result !== "object" || !("required" in result) || !("authenticated" in result) || typeof result.required !== "boolean" || typeof result.authenticated !== "boolean") {
    throw new Error("AUTH_CHECK_FAILED");
  }
  const actor = parseAuthActor("actor" in result ? result.actor : null);
  return {
    required: result.required,
    authenticated: result.authenticated,
    setup_required: "setup_required" in result && result.setup_required === true,
    ...(actor ? { actor } : {}),
  };
}

export async function logoutWeb(): Promise<void> {
  const response = await fetch(apiUrl("/api/auth/logout"), {
    method: "POST",
    credentials: "same-origin",
  });
  if (!response.ok) {
    throw new Error("AUTH_LOGOUT_FAILED");
  }
}

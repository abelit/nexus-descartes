<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { LoaderCircle, Pencil, Plus, ShieldCheck, Trash2 } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import * as api from "@/lib/backend/api";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type {
  AssetGrant,
  ConnectionGroup,
  EffectiveAccess,
  LocalRole,
  LocalUser,
  UserSession,
} from "@/lib/backend/users";

export interface AccessConnectionOption {
  id: string;
  name: string;
  db_type: string;
}

const props = defineProps<{
  open: boolean;
  user: LocalUser | null;
  roles: LocalRole[];
  groups: ConnectionGroup[];
  connections: AccessConnectionOption[];
  actorPermissions: string[];
  actorRoles?: string[];
  actorId?: string;
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "changed"): void;
}>();

const { t } = useI18n();
const { toast } = useToast();

const ASSET_PERMISSIONS = new Set([
  "connection:read",
  "query:read",
  "query:write",
  "query:ddl",
  "export:data",
  "import:data",
  "unmask:data",
  "row_filter:bypass",
]);

const CAPABILITY_LABELS: Record<string, string> = {
  "connection:read": "Browse",
  "query:read": "SELECT",
  "query:write": "DML",
  "query:ddl": "DDL",
  "export:data": "Export",
  "import:data": "Import",
  "unmask:data": "Unmask",
  "row_filter:bypass": "Row bypass",
  "approval:read": "Approvals",
  "approval:act": "Approve",
};

type TargetKind = AssetGrant["target_kind"];
type GrantStatus = "active" | "expiring" | "expired";
type ExpiryMode = "keep" | "never" | "custom";

const grants = ref<AssetGrant[]>([]);
const grantsLoading = ref(false);
const sessions = ref<UserSession[]>([]);
const sessionsLoading = ref(false);
const loadError = ref("");
const actionError = ref("");

const globalRole = ref("");
const savingGlobalRole = ref(false);

const grantFilter = ref("");
const statusFilter = ref<"all" | GrantStatus>("all");

const addForm = reactive({
  role_code: "",
  target_kind: "connection" as TargetKind,
  connection_group_id: "",
  connection_id: "",
  database_name: "",
  schema_name: "",
  table_name: "",
  name_pattern: false,
  expiry_mode: "never" as "never" | "1d" | "7d" | "30d" | "custom",
  expires_at: "",
  reason: "",
});

const databases = ref<string[]>([]);
const schemas = ref<string[]>([]);
const tables = ref<string[]>([]);
const metaLoading = reactive({ databases: false, schemas: false, tables: false });
const metaError = ref("");

const editing = ref<AssetGrant | null>(null);
const editForm = reactive({
  role_code: "",
  expiry_mode: "keep" as ExpiryMode,
  expires_at: "",
  reason: "",
});
const savingEdit = ref(false);

const deleteTarget = ref<AssetGrant | null>(null);
const deleting = ref(false);

const effective = ref<EffectiveAccess | null>(null);
const checkingAccess = ref(false);
const accessError = ref("");
const lastAccessQuery = ref<{ connection_id: string; database?: string; schema?: string; table?: string } | null>(null);

const assetRoles = computed(() =>
  props.roles.filter(
    (role) =>
      role.code !== "admin" &&
      !role.permissions.some((permission) => permission.startsWith("admin:")) &&
      role.permissions.some((permission) => ASSET_PERMISSIONS.has(permission)),
  ),
);

function defaultAssetRole(): string {
  return assetRoles.value.find((role) => role.code === "viewer")?.code ?? assetRoles.value[0]?.code ?? "";
}
const editRoleOptions = computed(() => {
  if (editing.value && !assetRoles.value.some((role) => role.code === editForm.role_code)) {
    const role = props.roles.find((candidate) => candidate.code === editForm.role_code);
    if (role) return [...assetRoles.value, role];
  }
  return assetRoles.value;
});

const actorGlobalPermissions = computed(() => {
  const codes = new Set(props.actorRoles ?? []);
  if (codes.size === 0) return props.actorPermissions;
  const permissions = new Set<string>();
  for (const role of props.roles) {
    if (codes.has(role.code)) for (const permission of role.permissions) permissions.add(permission);
  }
  return [...permissions];
});

const assignableRoles = computed(() => {
  if (actorGlobalPermissions.value.length === 0) return props.roles;
  return props.roles.filter((role) => role.permissions.every((permission) => actorGlobalPermissions.value.includes(permission)));
});

const globalRoleOptions = computed(() => {
  const current = props.user?.roles[0] ?? "";
  if (current && !assignableRoles.value.some((role) => role.code === current)) {
    const role = props.roles.find((candidate) => candidate.code === current);
    if (role) return [...assignableRoles.value, role];
  }
  return assignableRoles.value;
});

const currentGlobalRole = computed(() => props.user?.roles[0] ?? "");
const globalRoleDirty = computed(() => globalRole.value !== currentGlobalRole.value);

const selectedConnection = computed(() => props.connections.find((connection) => connection.id === addForm.connection_id));
const isMongo = computed(() => selectedConnection.value?.db_type === "mongodb");

const selectedRole = computed(() => props.roles.find((role) => role.code === addForm.role_code) ?? null);
const selectedCapabilities = computed(() => capabilitiesFor(addForm.role_code));
const selectedRoleExceedsCeiling = computed(() => {
  if (!selectedRole.value || props.actorPermissions.length === 0) return false;
  return selectedRole.value.permissions.some((permission) => !props.actorPermissions.includes(permission));
});

const tableOptions = computed(() => tables.value);
const wildcardMatches = computed(() => {
  if (addForm.target_kind !== "table" || !addForm.name_pattern || !addForm.table_name.trim()) return null;
  const pattern = addForm.table_name.trim();
  return tableOptions.value.filter((table) => wildcardMatch(pattern, table)).length;
});

const duplicateGrant = computed(() => {
  if (!props.user) return false;
  const database = needsDatabase.value ? addForm.database_name.trim() : "";
  const schema = needsSchema.value ? addForm.schema_name.trim() : "";
  const table = needsTable.value ? addForm.table_name.trim() : "";
  return grants.value.some(
    (grant) =>
      grant.role_code === addForm.role_code &&
      grant.target_kind === addForm.target_kind &&
      (grant.connection_group_id ?? "") === (addForm.target_kind === "connection_group" ? addForm.connection_group_id : "") &&
      (grant.connection_id ?? "") === (addForm.target_kind === "connection_group" ? "" : addForm.connection_id) &&
      (grant.database_name ?? "") === database &&
      (grant.schema_name ?? "") === schema &&
      (grant.table_name ?? "") === table &&
      grant.name_pattern === (needsTable.value ? addForm.name_pattern : false),
  );
});

const needsDatabase = computed(() => ["database", "schema", "table"].includes(addForm.target_kind));
const needsSchema = computed(() => ["schema", "table"].includes(addForm.target_kind) && !isMongo.value);
const needsTable = computed(() => addForm.target_kind === "table");

const filteredGrants = computed(() => {
  const query = grantFilter.value.trim().toLowerCase();
  return grants.value
    .filter((grant) => statusFilter.value === "all" || grantStatus(grant) === statusFilter.value)
    .filter((grant) => {
      if (!query) return true;
      return [grantTargetLabel(grant), grant.role_code, grant.reason, grant.granted_by].some((value) =>
        (value ?? "").toLowerCase().includes(query),
      );
    })
    .sort((left, right) => statusRank(left) - statusRank(right) || grantTargetLabel(left).localeCompare(grantTargetLabel(right)));
});

const grantCounts = computed(() => {
  const counts = { active: 0, expiring: 0, expired: 0 };
  for (const grant of grants.value) counts[grantStatus(grant)] += 1;
  return counts;
});

const canSubmitGrant = computed(() => {
  if (!addForm.role_code || duplicateGrant.value) return false;
  if (isMongo.value && addForm.target_kind === "schema") return false;
  if (addForm.target_kind === "connection_group") return !!addForm.connection_group_id;
  if (!addForm.connection_id) return false;
  if (needsDatabase.value && !addForm.database_name.trim()) return false;
  if (needsSchema.value && !addForm.schema_name.trim()) return false;
  if (needsTable.value && !addForm.table_name.trim()) return false;
  if (addForm.expiry_mode === "custom" && !validCustomExpiry(addForm.expires_at)) return false;
  return true;
});

function capabilitiesFor(roleCode: string): string[] {
  const role = props.roles.find((candidate) => candidate.code === roleCode);
  if (!role) return [];
  return [
    ...new Set(
      role.permissions
        .filter((permission) => ASSET_PERMISSIONS.has(permission))
        .map((permission) => CAPABILITY_LABELS[permission] ?? permission),
    ),
  ];
}

function statusRank(grant: AssetGrant): number {
  return { expiring: 0, active: 1, expired: 2 }[grantStatus(grant)];
}

function grantStatus(grant: AssetGrant): GrantStatus {
  if (!grant.expires_at) return "active";
  const expires = Date.parse(grant.expires_at);
  if (Number.isNaN(expires)) return "active";
  const remaining = expires - Date.now();
  if (remaining <= 0) return "expired";
  if (remaining <= 7 * 24 * 60 * 60 * 1000) return "expiring";
  return "active";
}

function statusClass(status: GrantStatus): string {
  switch (status) {
    case "expired":
      return "border-destructive/50 text-destructive";
    case "expiring":
      return "border-amber-500/50 text-amber-600 dark:text-amber-400";
    default:
      return "border-green-500/40 text-green-600 dark:text-green-400";
  }
}

function grantTargetLabel(grant: AssetGrant): string {
  if (grant.target_kind === "connection_group") return props.groups.find((group) => group.id === grant.connection_group_id)?.name ?? grant.connection_group_id ?? t("settings.identity.targetGroup");
  const connection = props.connections.find((candidate) => candidate.id === grant.connection_id)?.name ?? grant.connection_id ?? "—";
  if (grant.target_kind === "connection") return connection;
  const base = `${connection} · ${grant.database_name ?? ""}`;
  if (grant.target_kind === "database") return base;
  if (grant.target_kind === "schema") return `${base} / ${grant.schema_name ?? ""}`;
  return `${base} / ${grant.schema_name ?? ""} / ${grant.table_name ?? ""}`;
}

function formatDate(value?: string | null): string {
  if (!value) return t("settings.identity.expiryNever");
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function toLocalInput(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (part: number) => String(part).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function validCustomExpiry(value: string): boolean {
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.getTime() > Date.now();
}

function expiryForAdd(): string | null | undefined {
  if (addForm.expiry_mode === "never") return null;
  if (addForm.expiry_mode === "custom") {
    const parsed = new Date(addForm.expires_at);
    return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
  }
  const days = addForm.expiry_mode === "1d" ? 1 : addForm.expiry_mode === "7d" ? 7 : 30;
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function editExpiry(): { keep?: true; value?: string | null } {
  if (editForm.expiry_mode === "keep") return { keep: true };
  if (editForm.expiry_mode === "never") return { value: null };
  const parsed = new Date(editForm.expires_at);
  return Number.isNaN(parsed.getTime()) ? { keep: true } : { value: parsed.toISOString() };
}

function wildcardMatch(pattern: string, value: string): boolean {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  try {
    return new RegExp(`^${escaped}$`, "i").test(value);
  } catch {
    return pattern.toLowerCase() === value.toLowerCase();
  }
}

async function initialize() {
  if (!props.user) return;
  loadError.value = "";
  actionError.value = "";
  grants.value = [];
  sessions.value = [];
  effective.value = null;
  lastAccessQuery.value = null;
  globalRole.value = props.user.roles[0] ?? "";
  resetGrantForm();
  await Promise.all([loadGrants(), loadSessions()]);
}

function resetGrantForm() {
  addForm.role_code = defaultAssetRole();
  addForm.target_kind = "connection";
  addForm.connection_group_id = "";
  addForm.connection_id = "";
  addForm.database_name = "";
  addForm.schema_name = "";
  addForm.table_name = "";
  addForm.name_pattern = false;
  addForm.expiry_mode = "never";
  addForm.expires_at = "";
  addForm.reason = "";
  databases.value = [];
  schemas.value = [];
  tables.value = [];
  metaError.value = "";
}

async function loadGrants() {
  if (!props.user) return;
  grantsLoading.value = true;
  try {
    grants.value = await usersApi.listAssetGrants(props.user.id);
  } catch (error) {
    loadError.value = formatError(error);
  } finally {
    grantsLoading.value = false;
  }
}

async function loadSessions() {
  if (!props.user) return;
  sessionsLoading.value = true;
  try {
    sessions.value = await usersApi.listUserSessions(props.user.id);
  } catch {
    sessions.value = [];
  } finally {
    sessionsLoading.value = false;
  }
}

async function loadDatabases() {
  databases.value = [];
  schemas.value = [];
  tables.value = [];
  metaError.value = "";
  if (!addForm.connection_id || !selectedConnection.value) return;
  metaLoading.databases = true;
  try {
    const names = isMongo.value
      ? await api.mongoListDatabases(addForm.connection_id)
      : (await api.listDatabases(addForm.connection_id)).map((database) => database.name);
    databases.value = [...new Set(names)].sort((left, right) => left.localeCompare(right));
  } catch (error) {
    metaError.value = formatError(error);
  } finally {
    metaLoading.databases = false;
  }
}

async function loadSchemas() {
  schemas.value = [];
  tables.value = [];
  if (!addForm.connection_id || !addForm.database_name || isMongo.value) return;
  metaLoading.schemas = true;
  metaError.value = "";
  try {
    schemas.value = (await api.listSchemas(addForm.connection_id, addForm.database_name)).sort((left, right) => left.localeCompare(right));
    // MySQL and MariaDB have no separate schema namespace, and some drivers
    // return an empty list; use the database name so the table cascade can
    // continue without asking the administrator to retype it.
    if (!addForm.schema_name && (schemas.value.length === 0 || schemas.value.length === 1)) {
      addForm.schema_name = schemas.value[0] ?? addForm.database_name;
    }
  } catch (error) {
    metaError.value = formatError(error);
  } finally {
    metaLoading.schemas = false;
  }
}

async function loadTables() {
  tables.value = [];
  if (!addForm.connection_id || !addForm.database_name) return;
  if (!isMongo.value && !addForm.schema_name) return;
  metaLoading.tables = true;
  metaError.value = "";
  try {
    const names = isMongo.value
      ? (await api.mongoListCollections(addForm.connection_id, addForm.database_name)).map((collection) => collection.name)
      : (await api.listTables(addForm.connection_id, addForm.database_name, addForm.schema_name)).map((table) => table.name);
    tables.value = [...new Set(names)].sort((left, right) => left.localeCompare(right));
  } catch (error) {
    metaError.value = formatError(error);
  } finally {
    metaLoading.tables = false;
  }
}

function onTargetKindChange() {
  addForm.database_name = "";
  addForm.schema_name = "";
  addForm.table_name = "";
  addForm.name_pattern = false;
  databases.value = [];
  schemas.value = [];
  tables.value = [];
}

async function addGrant() {
  if (!props.user || !canSubmitGrant.value) return;
  const expires = expiryForAdd();
  if (expires === undefined) {
    actionError.value = t("settings.identity.invalidGrant");
    return;
  }
  actionError.value = "";
  try {
    await usersApi.createAssetGrant(props.user.id, {
      role_code: addForm.role_code,
      target_kind: addForm.target_kind,
      connection_group_id: addForm.target_kind === "connection_group" ? addForm.connection_group_id : null,
      connection_id: addForm.target_kind === "connection_group" ? null : addForm.connection_id,
      database_name: needsDatabase.value ? addForm.database_name.trim() : null,
      schema_name: needsSchema.value ? addForm.schema_name.trim() : null,
      table_name: needsTable.value ? addForm.table_name.trim() : null,
      name_pattern: needsTable.value ? addForm.name_pattern : false,
      expires_at: expires,
      reason: addForm.reason.trim(),
    });
    toast(t("settings.identity.grantCreated"));
    // Keep the target selected: it is the context for "Check effective
    // access", and duplicateGrant now prevents adding the same grant twice.
    addForm.reason = "";
    addForm.expiry_mode = "never";
    addForm.expires_at = "";
    await reloadAfterMutation();
  } catch (error) {
    actionError.value = formatError(error);
    toast(actionError.value);
  }
}

async function reloadAfterMutation() {
  await Promise.all([loadGrants(), loadSessions()]);
  emit("changed");
  if (lastAccessQuery.value) await checkEffectiveAccess(true);
}

function startEdit(grant: AssetGrant) {
  editing.value = grant;
  editForm.role_code = grant.role_code;
  editForm.expiry_mode = grant.expires_at ? "custom" : "never";
  editForm.expires_at = grant.expires_at ? toLocalInput(grant.expires_at) : "";
  editForm.reason = grant.reason;
}

async function saveEdit() {
  if (!props.user || !editing.value) return;
  if (editForm.expiry_mode === "custom" && !validCustomExpiry(editForm.expires_at)) {
    actionError.value = t("settings.identity.invalidGrant");
    return;
  }
  const expiry = editExpiry();
  savingEdit.value = true;
  actionError.value = "";
  try {
    await usersApi.updateAssetGrant(props.user.id, editing.value.id, {
      role_code: editForm.role_code,
      ...(expiry.keep ? {} : { expires_at: expiry.value ?? null }),
      reason: editForm.reason.trim(),
    });
    editing.value = null;
    toast(t("settings.identity.grantUpdated"));
    await reloadAfterMutation();
  } catch (error) {
    actionError.value = formatError(error);
    toast(actionError.value);
  } finally {
    savingEdit.value = false;
  }
}

async function confirmDelete() {
  if (!props.user || !deleteTarget.value) return;
  deleting.value = true;
  try {
    await usersApi.deleteAssetGrant(props.user.id, deleteTarget.value.id);
    deleteTarget.value = null;
    toast(t("settings.identity.grantRemoved"));
    await reloadAfterMutation();
  } catch (error) {
    actionError.value = formatError(error);
    toast(actionError.value);
  } finally {
    deleting.value = false;
  }
}

async function saveGlobalRole() {
  if (!props.user || !globalRoleDirty.value) return;
  savingGlobalRole.value = true;
  actionError.value = "";
  try {
    if (!globalRole.value) {
      await usersApi.updateUser(props.user.id, { clear_global_role: true });
    } else {
      await usersApi.updateUser(props.user.id, { role: globalRole.value });
    }
    toast(t("settings.identity.roleUpdated"));
    emit("changed");
  } catch (error) {
    actionError.value = formatError(error);
    toast(actionError.value);
  } finally {
    savingGlobalRole.value = false;
  }
}

function accessQuery(): { connection_id: string; database?: string; schema?: string; table?: string } | null {
  if (!addForm.connection_id) return null;
  if (addForm.target_kind === "connection_group") return null;
  return {
    connection_id: addForm.connection_id,
    database: needsDatabase.value ? addForm.database_name.trim() || undefined : undefined,
    schema: needsSchema.value ? addForm.schema_name.trim() || undefined : undefined,
    table: needsTable.value ? addForm.table_name.trim() || undefined : undefined,
  };
}

async function checkEffectiveAccess(silent = false) {
  if (!props.user) return;
  const query = accessQuery();
  if (!query) {
    if (!silent) accessError.value = t("settings.identity.accessCheckFailed");
    return;
  }
  checkingAccess.value = true;
  accessError.value = "";
  lastAccessQuery.value = query;
  try {
    effective.value = await usersApi.effectiveAccess(props.user.id, query);
  } catch (error) {
    effective.value = null;
    accessError.value = formatError(error);
  } finally {
    checkingAccess.value = false;
  }
}

const assetPermissionRows = computed(() => effective.value?.permissions.filter((permission) => permission.asset_scopeable) ?? []);

async function revokeAllSessions() {
  if (!props.user) return;
  try {
    await usersApi.revokeUserSessions(props.user.id);
    toast(t("settings.identity.sessionsRevoked"));
    await loadSessions();
  } catch (error) {
    toast(formatError(error));
  }
}

async function revokeSession(session: UserSession) {
  if (!props.user) return;
  try {
    await usersApi.revokeUserSession(props.user.id, session.id);
    await loadSessions();
  } catch (error) {
    toast(formatError(error));
  }
}

watch(
  () => props.open,
  (open) => {
    if (open) void initialize();
  },
);

watch(
  () => props.user?.id,
  () => {
    if (props.open) void initialize();
  },
);

watch(assetRoles, () => {
  if (!addForm.role_code) addForm.role_code = defaultAssetRole();
});

watch(isMongo, (mongo) => {
  if (mongo && addForm.target_kind === "schema") addForm.target_kind = "database";
});

watch(
  () => [addForm.connection_id, addForm.database_name, addForm.schema_name, addForm.table_name, addForm.target_kind] as const,
  () => {
    effective.value = null;
    accessError.value = "";
    lastAccessQuery.value = null;
  },
);

watch(
  () => addForm.connection_id,
  () => {
    addForm.database_name = "";
    addForm.schema_name = "";
    addForm.table_name = "";
    if (!needsDatabase.value) return;
    void loadDatabases();
  },
);

watch(
  () => addForm.database_name,
  () => {
    addForm.schema_name = "";
    addForm.table_name = "";
    if (!needsSchema.value && !needsTable.value) return;
    void loadSchemas();
  },
);

watch(
  () => addForm.schema_name,
  () => {
    addForm.table_name = "";
    if (!needsTable.value) return;
    void loadTables();
  },
);

watch(
  () => addForm.target_kind,
  () => {
    onTargetKindChange();
    if (needsDatabase.value && addForm.connection_id) void loadDatabases();
  },
);
</script>

<template>
  <Dialog :open="props.open" @update:open="(value) => emit('update:open', value)">
    <DialogContent class="flex h-[calc(var(--dbx-viewport-height)-2rem)] w-full max-w-3xl flex-col gap-0 overflow-hidden p-0">
      <div class="shrink-0 border-b border-border px-4 py-3 pr-12">
        <DialogTitle class="text-base font-medium">
          {{ t("settings.identity.accessDialogTitle", { name: user?.display_name || user?.email || "" }) }}
        </DialogTitle>
        <p class="mt-1 text-xs text-muted-foreground">{{ user?.email }}</p>
      </div>

      <div v-if="!props.user" class="p-6 text-sm text-muted-foreground">{{ t("settings.identity.empty") }}</div>
      <div v-else class="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-4">
        <p v-if="loadError" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">{{ loadError }}</p>
        <p v-if="actionError" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">{{ actionError }}</p>

        <section class="space-y-2 rounded-lg border border-border/60 p-3">
          <div class="flex flex-wrap items-start justify-between gap-2">
            <div>
              <div class="text-sm font-medium">{{ t("settings.identity.globalRole") }}</div>
              <p class="text-xs text-muted-foreground">{{ t("settings.identity.globalRoleHint") }}</p>
            </div>
            <Badge v-if="user?.is_builtin" variant="outline">{{ t("settings.identity.roleCapability") }}: admin</Badge>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <select v-model="globalRole" class="h-8 min-w-48 rounded-md border border-input bg-background px-2 text-sm" :disabled="user?.is_builtin || savingGlobalRole">
              <option value="">{{ t("settings.identity.noGlobalRole") }}</option>
              <option v-for="role in globalRoleOptions" :key="role.code" :value="role.code">{{ role.name }}</option>
            </select>
            <Button size="sm" :disabled="!globalRoleDirty || savingGlobalRole || user?.is_builtin" @click="saveGlobalRole">
              <LoaderCircle v-if="savingGlobalRole" class="mr-1 h-3.5 w-3.5 animate-spin" />
              {{ t("settings.identity.saveRole") }}
            </Button>
            <span v-if="globalRoleDirty && !globalRoleOptions.some((role) => role.code === globalRole)" class="text-xs text-destructive">
              {{ t("settings.identity.roleAboveCeiling") }}
            </span>
          </div>
        </section>

        <section class="space-y-3 rounded-lg border border-border/60 p-3">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div class="text-sm font-medium">{{ t("settings.identity.assetGrantsTitle") }}</div>
              <p class="text-xs text-muted-foreground">
                {{ grantCounts.active }} {{ t("settings.identity.grantStatusActive") }} · {{ grantCounts.expiring }} {{ t("settings.identity.grantStatusExpiring") }} · {{ grantCounts.expired }} {{ t("settings.identity.grantStatusExpired") }}
              </p>
            </div>
            <LoaderCircle v-if="grantsLoading" class="h-4 w-4 animate-spin text-muted-foreground" />
          </div>

          <div class="flex flex-wrap items-center gap-2">
            <Input v-model="grantFilter" class="h-8 w-52" :placeholder="t('settings.identity.grantFilter')" />
            <select v-model="statusFilter" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
              <option value="all">{{ t("settings.identity.grantStatusAll") }}</option>
              <option value="active">{{ t("settings.identity.grantStatusActive") }}</option>
              <option value="expiring">{{ t("settings.identity.grantStatusExpiring") }}</option>
              <option value="expired">{{ t("settings.identity.grantStatusExpired") }}</option>
            </select>
          </div>

          <p v-if="!grantsLoading && grants.length === 0" class="text-xs text-muted-foreground">{{ t("settings.identity.noGrants") }}</p>
          <p v-else-if="filteredGrants.length === 0" class="text-xs text-muted-foreground">{{ t("settings.identity.emptyFiltered") }}</p>

          <div class="space-y-2">
            <div v-for="grant in filteredGrants" :key="grant.id" class="space-y-1 rounded-md border border-border/50 px-2 py-2 text-xs">
              <div class="flex flex-wrap items-center gap-2">
                <Badge variant="outline">{{ grant.role_code }}</Badge>
                <Badge v-if="grant.principal_type === 'group'" variant="secondary">{{ t("settings.identity.principalGroup") }}</Badge>
                <span class="min-w-0 flex-1 truncate font-medium" :title="grantTargetLabel(grant)">{{ grantTargetLabel(grant) }}</span>
                <Badge variant="outline" :class="statusClass(grantStatus(grant))">{{ t(`settings.identity.grantStatus${grantStatus(grant)[0].toUpperCase()}${grantStatus(grant).slice(1)}`) }}</Badge>
                <Button v-if="grant.principal_type !== 'group'" size="sm" variant="outline" class="h-6 px-1.5" :title="t('settings.identity.editGrant')" @click="startEdit(grant)">
                  <Pencil class="h-3 w-3" />
                </Button>
                <Button v-if="grant.principal_type !== 'group'" size="sm" variant="outline" class="h-6 px-1.5 text-destructive" :title="t('settings.identity.removeGrant')" @click="deleteTarget = grant">
                  <Trash2 class="h-3 w-3" />
                </Button>
              </div>
              <div class="flex flex-wrap items-center gap-1.5 text-muted-foreground">
                <span v-for="capability in capabilitiesFor(grant.role_code)" :key="capability" class="rounded border border-border/60 px-1 py-0.5">{{ capability }}</span>
                <span v-if="grant.name_pattern" class="rounded border border-border/60 px-1 py-0.5">* / ?</span>
                <span>{{ formatDate(grant.expires_at) }}</span>
                <span v-if="grant.granted_by" class="max-w-48 truncate" :title="grant.granted_by">· {{ t("settings.identity.inventoryGrantedBy") }}: {{ grant.granted_by }}</span>
                <span v-if="grant.reason" class="max-w-64 truncate" :title="grant.reason">· {{ grant.reason }}</span>
              </div>
            </div>
          </div>

          <div v-if="editing" class="space-y-2 rounded-md border border-primary/30 bg-primary/5 p-2">
            <div class="text-xs font-medium">{{ t("settings.identity.editGrant") }}: {{ grantTargetLabel(editing) }}</div>
            <div class="flex flex-wrap items-center gap-2">
              <select v-model="editForm.role_code" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
                <option v-for="role in editRoleOptions" :key="role.code" :value="role.code">{{ role.name }}</option>
              </select>
              <select v-model="editForm.expiry_mode" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
                <option value="keep">{{ t("settings.identity.keepExpiry") }}</option>
                <option value="never">{{ t("settings.identity.expiryNever") }}</option>
                <option value="custom">{{ t("settings.identity.expiryCustom") }}</option>
              </select>
              <Input v-if="editForm.expiry_mode === 'custom'" v-model="editForm.expires_at" type="datetime-local" class="h-8 w-48" />
              <Input v-model="editForm.reason" class="h-8 w-48" :placeholder="t('settings.identity.grantReason')" />
              <Button size="sm" :disabled="savingEdit" @click="saveEdit">
                <LoaderCircle v-if="savingEdit" class="mr-1 h-3.5 w-3.5 animate-spin" />
                {{ t("settings.identity.saveGrant") }}
              </Button>
              <Button size="sm" variant="outline" @click="editing = null">{{ t("settings.identity.cancel") }}</Button>
            </div>
          </div>

          <div class="space-y-2 border-t border-border/50 pt-3">
            <div class="text-xs font-medium">{{ t("settings.identity.addGrant") }}</div>
            <div class="flex flex-wrap items-center gap-2">
              <select v-model="addForm.role_code" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
                <option v-for="role in assetRoles" :key="role.code" :value="role.code">{{ role.name }}</option>
              </select>
              <select v-model="addForm.target_kind" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
                <option value="connection">{{ t("settings.identity.targetConnection") }}</option>
                <option value="connection_group">{{ t("settings.identity.targetGroup") }}</option>
                <option value="database">{{ t("settings.identity.targetDatabase") }}</option>
                <option value="schema" :disabled="isMongo">{{ t("settings.identity.targetSchema") }}</option>
                <option value="table">{{ t("settings.identity.targetTable") }}</option>
              </select>
              <select v-if="addForm.target_kind === 'connection_group'" v-model="addForm.connection_group_id" class="h-8 max-w-52 rounded-md border border-input bg-background px-2 text-sm">
                <option value="">{{ t("settings.identity.scopeSelect") }}</option>
                <option v-for="group in groups" :key="group.id" :value="group.id">{{ group.name }}</option>
              </select>
              <select v-else v-model="addForm.connection_id" class="h-8 max-w-52 rounded-md border border-input bg-background px-2 text-sm">
                <option value="">{{ t("settings.identity.selectConnection") }}</option>
                <option v-for="connection in connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
              </select>
            </div>
            <div v-if="needsDatabase" class="grid gap-2 sm:grid-cols-3">
              <label class="space-y-1 text-xs text-muted-foreground">
                <span>{{ t("settings.identity.scopeDatabaseName") }}</span>
                <span class="flex items-center gap-1">
                  <Input v-model="addForm.database_name" list="access-database-options" class="h-8" :placeholder="t('settings.identity.selectDatabase')" />
                  <LoaderCircle v-if="metaLoading.databases" class="h-3.5 w-3.5 shrink-0 animate-spin" />
                </span>
              </label>
              <label v-if="needsSchema" class="space-y-1 text-xs text-muted-foreground">
                <span>{{ t("settings.identity.scopeSchemaName") }}</span>
                <span class="flex items-center gap-1">
                  <Input v-model="addForm.schema_name" list="access-schema-options" class="h-8" :placeholder="t('settings.identity.selectSchema')" />
                  <LoaderCircle v-if="metaLoading.schemas" class="h-3.5 w-3.5 shrink-0 animate-spin" />
                </span>
              </label>
              <label v-if="needsTable" class="space-y-1 text-xs text-muted-foreground">
                <span>{{ t("settings.identity.scopeTableName") }}</span>
                <span class="flex items-center gap-1">
                  <Input v-model="addForm.table_name" list="access-table-options" class="h-8" :placeholder="t('settings.identity.selectTable')" />
                  <LoaderCircle v-if="metaLoading.tables" class="h-3.5 w-3.5 shrink-0 animate-spin" />
                </span>
              </label>
              <datalist id="access-database-options">
                <option v-for="database in databases" :key="database" :value="database" />
              </datalist>
              <datalist id="access-schema-options">
                <option v-for="schema in schemas" :key="schema" :value="schema" />
              </datalist>
              <datalist id="access-table-options">
                <option v-for="table in tables" :key="table" :value="table" />
              </datalist>
            </div>
            <label v-if="needsTable" class="flex items-center gap-1 text-xs text-muted-foreground">
              <input v-model="addForm.name_pattern" type="checkbox" />
              {{ t("settings.identity.usePattern") }}
            </label>
            <p v-if="metaError" class="text-xs text-destructive">{{ metaError }}</p>
            <p class="text-xs text-muted-foreground">{{ t("settings.identity.manualEntryHint") }}</p>
            <div class="flex flex-wrap items-center gap-2">
              <select v-model="addForm.expiry_mode" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
                <option value="never">{{ t("settings.identity.expiryNever") }}</option>
                <option value="1d">{{ t("settings.identity.expiry1d") }}</option>
                <option value="7d">{{ t("settings.identity.expiry7d") }}</option>
                <option value="30d">{{ t("settings.identity.expiry30d") }}</option>
                <option value="custom">{{ t("settings.identity.expiryCustom") }}</option>
              </select>
              <Input v-if="addForm.expiry_mode === 'custom'" v-model="addForm.expires_at" type="datetime-local" class="h-8 w-48" />
              <Input v-model="addForm.reason" class="h-8 w-48" :placeholder="t('settings.identity.grantReason')" />
              <Button size="sm" :disabled="!canSubmitGrant" @click="addGrant">
                <Plus class="mr-1 h-3.5 w-3.5" />
                {{ t("settings.identity.addGrant") }}
              </Button>
            </div>
            <div class="flex flex-wrap items-center gap-1.5 text-xs">
              <span v-for="capability in selectedCapabilities" :key="capability" class="rounded border border-border/60 px-1 py-0.5 text-muted-foreground">{{ capability }}</span>
              <span v-if="wildcardMatches !== null" class="text-muted-foreground">{{ t("settings.identity.patternPreview", { count: wildcardMatches }) }}</span>
              <span v-if="duplicateGrant" class="text-amber-600 dark:text-amber-400">{{ t("settings.identity.duplicateGrant") }}</span>
              <span v-if="selectedRoleExceedsCeiling" class="text-amber-600 dark:text-amber-400">{{ t("settings.identity.grantCeilingHint") }}</span>
              <span v-if="user?.id === actorId" class="text-muted-foreground">{{ t("settings.identity.selfGrantHint") }}</span>
            </div>
          </div>
        </section>

        <section class="space-y-2 rounded-lg border border-border/60 p-3">
          <div class="flex flex-wrap items-center justify-between gap-2">
            <div>
              <div class="text-sm font-medium">{{ t("settings.identity.effectiveAccessTitle") }}</div>
              <p class="text-xs text-muted-foreground">{{ t("settings.identity.effectiveAccessHint") }}</p>
            </div>
            <Button size="sm" variant="outline" :disabled="checkingAccess" @click="checkEffectiveAccess()">
              <LoaderCircle v-if="checkingAccess" class="mr-1 h-3.5 w-3.5 animate-spin" />
              <ShieldCheck v-else class="mr-1 h-3.5 w-3.5" />
              {{ checkingAccess ? t("settings.identity.checkingAccess") : t("settings.identity.checkAccess") }}
            </Button>
          </div>
          <p v-if="accessError" class="text-xs text-destructive">{{ accessError }}</p>
          <div v-if="effective" class="space-y-2 text-xs">
            <div class="flex flex-wrap gap-1.5">
              <span v-for="permission in assetPermissionRows.filter((row) => row.allowed)" :key="permission.permission" class="rounded border border-green-500/40 bg-green-500/10 px-1.5 py-0.5 text-green-700 dark:text-green-400">
                {{ permission.permission }}<span v-if="permission.broad"> · {{ t("settings.identity.broadCoverage") }}</span>
              </span>
              <span v-for="permission in assetPermissionRows.filter((row) => !row.allowed)" :key="permission.permission" class="rounded border border-border/60 px-1.5 py-0.5 text-muted-foreground/60">
                {{ permission.permission }}
              </span>
            </div>
            <div class="flex flex-wrap gap-2 text-muted-foreground">
              <span>{{ t("settings.identity.navigationAccess") }}:</span>
              <Badge variant="outline" :class="effective.can_navigate_connection ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground'">{{ t("settings.identity.columnConnection") }}</Badge>
              <Badge v-if="effective.database" variant="outline" :class="effective.can_navigate_database ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground'">{{ t("settings.identity.columnDatabase") }}</Badge>
              <Badge v-if="effective.schema" variant="outline" :class="effective.can_navigate_schema ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground'">{{ t("settings.identity.columnSchema") }}</Badge>
            </div>
            <div class="text-muted-foreground">{{ t("settings.identity.matchedGrants", { count: effective.permissions.reduce((sum, row) => sum + row.grant_ids.length, 0) }) }}</div>
          </div>
        </section>

        <section class="space-y-2 rounded-lg border border-border/60 p-3">
          <div class="flex items-center justify-between gap-2">
            <div class="text-sm font-medium">{{ t("settings.identity.sessions") }}</div>
            <Button size="sm" variant="outline" class="h-6 text-xs" :disabled="sessionsLoading" @click="revokeAllSessions">
              {{ t("settings.identity.revokeAll") }}
            </Button>
          </div>
          <p v-if="sessions.length === 0" class="text-xs text-muted-foreground">{{ t("settings.identity.noSessions") }}</p>
          <div v-for="session in sessions" :key="session.id" class="flex items-center justify-between gap-2 text-xs">
            <span class="min-w-0 truncate text-muted-foreground">{{ session.client_ip || "—" }} · {{ session.user_agent || "—" }} · {{ formatDate(new Date(session.last_seen_at_ms).toISOString()) }}</span>
            <Button size="sm" variant="outline" class="h-6 px-1.5" @click="revokeSession(session)">
              <Trash2 class="h-3 w-3" />
            </Button>
          </div>
        </section>
      </div>
    </DialogContent>
  </Dialog>

  <Dialog :open="!!deleteTarget" @update:open="(value) => !value && (deleteTarget = null)">
    <DialogContent class="sm:max-w-md">
      <DialogTitle>{{ t("settings.identity.deleteGrantTitle") }}</DialogTitle>
      <p class="text-sm text-muted-foreground">{{ t("settings.identity.deleteGrantConfirm", { name: user?.display_name || user?.email || "" }) }}</p>
      <p class="text-xs text-muted-foreground">{{ t("settings.identity.deleteGrantImpact") }}</p>
      <div class="flex justify-end gap-2">
        <Button variant="outline" size="sm" @click="deleteTarget = null">{{ t("settings.identity.cancel") }}</Button>
        <Button variant="destructive" size="sm" :disabled="deleting" @click="confirmDelete">
          <LoaderCircle v-if="deleting" class="mr-1 h-3.5 w-3.5 animate-spin" />
          {{ t("settings.identity.removeGrant") }}
        </Button>
      </div>
    </DialogContent>
  </Dialog>
</template>

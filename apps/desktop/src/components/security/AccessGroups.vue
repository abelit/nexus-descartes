<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import { LoaderCircle, Pencil, Plus, RefreshCw, Trash2, UserPlus, X } from "@lucide/vue";
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
  AssetGroup,
  AssetGroupDetail,
  ConnectionGroup,
  LocalRole,
  LocalUser,
} from "@/lib/backend/users";

export interface GroupConnectionOption {
  id: string;
  name: string;
  db_type: string;
}

const props = defineProps<{
  users: LocalUser[];
  roles: LocalRole[];
  connectionGroups: ConnectionGroup[];
  connections: GroupConnectionOption[];
}>();

const emit = defineEmits<{
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
]);

type TargetKind = AssetGrant["target_kind"];

const groups = ref<AssetGroup[]>([]);
const loading = ref(false);
const error = ref("");
const actionError = ref("");
const saving = ref(false);

const createDraft = reactive({ name: "", description: "" });

const manageOpen = ref(false);
const manageGroupId = ref("");
const detail = ref<AssetGroupDetail | null>(null);
const detailLoading = ref(false);
const nameDraft = ref("");
const descriptionDraft = ref("");
const memberDraft = ref("");
const deletingGroup = ref<AssetGroup | null>(null);
const deleting = ref(false);

const grantForm = reactive({
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

const assetRoles = computed(() =>
  props.roles.filter(
    (role) =>
      role.code !== "admin" &&
      !role.permissions.some((permission) => permission.startsWith("admin:")) &&
      role.permissions.some((permission) => ASSET_PERMISSIONS.has(permission)),
  ),
);

const selectedConnection = computed(() => props.connections.find((connection) => connection.id === grantForm.connection_id));
const isMongo = computed(() => selectedConnection.value?.db_type === "mongodb");
const needsDatabase = computed(() => ["database", "schema", "table"].includes(grantForm.target_kind));
const needsSchema = computed(() => ["schema", "table"].includes(grantForm.target_kind) && !isMongo.value);
const needsTable = computed(() => grantForm.target_kind === "table");

const existingMemberIds = computed(() => new Set(detail.value?.members.map((member) => member.user_id) ?? []));
const memberOptions = computed(() =>
  props.users
    .filter((user) => !existingMemberIds.value.has(user.id) && user.status !== "disabled")
    .sort((left, right) => (left.display_name || left.email).localeCompare(right.display_name || right.email)),
);

const canAddGrant = computed(() => {
  if (!grantForm.role_code) return false;
  if (grantForm.target_kind === "connection_group") return !!grantForm.connection_group_id;
  if (!grantForm.connection_id) return false;
  if (needsDatabase.value && !grantForm.database_name.trim()) return false;
  if (needsSchema.value && !grantForm.schema_name.trim()) return false;
  if (needsTable.value && !grantForm.table_name.trim()) return false;
  if (grantForm.expiry_mode === "custom") {
    const expires = new Date(grantForm.expires_at);
    if (Number.isNaN(expires.getTime()) || expires.getTime() <= Date.now()) return false;
  }
  return true;
});

function defaultRole(): string {
  return assetRoles.value.find((role) => role.code === "viewer")?.code ?? assetRoles.value[0]?.code ?? "";
}

function resetGrantForm() {
  grantForm.role_code = defaultRole();
  grantForm.target_kind = "connection";
  grantForm.connection_group_id = "";
  grantForm.connection_id = "";
  grantForm.database_name = "";
  grantForm.schema_name = "";
  grantForm.table_name = "";
  grantForm.name_pattern = false;
  grantForm.expiry_mode = "never";
  grantForm.expires_at = "";
  grantForm.reason = "";
  databases.value = [];
  schemas.value = [];
  tables.value = [];
}

function expiryForAdd(): string | null | undefined {
  if (grantForm.expiry_mode === "never") return null;
  if (grantForm.expiry_mode === "custom") {
    const parsed = new Date(grantForm.expires_at);
    return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
  }
  const days = grantForm.expiry_mode === "1d" ? 1 : grantForm.expiry_mode === "7d" ? 7 : 30;
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
}

function formatDate(value?: string | null): string {
  if (!value) return t("settings.identity.expiryNever");
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function targetLabel(grant: AssetGrant): string {
  if (grant.target_kind === "connection_group") {
    return props.connectionGroups.find((group) => group.id === grant.connection_group_id)?.name ?? grant.connection_group_id ?? t("settings.identity.targetGroup");
  }
  const connection = props.connections.find((candidate) => candidate.id === grant.connection_id)?.name ?? grant.connection_id ?? "—";
  if (grant.target_kind === "connection") return connection;
  const base = `${connection} · ${grant.database_name ?? ""}`;
  if (grant.target_kind === "database") return base;
  if (grant.target_kind === "schema") return `${base} / ${grant.schema_name ?? ""}`;
  return `${base} / ${grant.schema_name ?? ""} / ${grant.table_name ?? ""}`;
}

function roleLabel(code: string): string {
  return props.roles.find((role) => role.code === code)?.name ?? code;
}

async function loadGroups() {
  loading.value = true;
  error.value = "";
  try {
    groups.value = await usersApi.listAssetGroups();
  } catch (loadError) {
    error.value = formatError(loadError);
    groups.value = [];
  } finally {
    loading.value = false;
  }
}

async function createGroup() {
  const name = createDraft.name.trim();
  if (!name) return;
  saving.value = true;
  try {
    await usersApi.createAssetGroup({ name, description: createDraft.description.trim() });
    createDraft.name = "";
    createDraft.description = "";
    toast(t("settings.identity.groupCreated"));
    await loadGroups();
  } catch (createError) {
    toast(formatError(createError));
  } finally {
    saving.value = false;
  }
}

async function openManage(group: AssetGroup) {
  manageGroupId.value = group.id;
  nameDraft.value = group.name;
  descriptionDraft.value = group.description;
  memberDraft.value = "";
  actionError.value = "";
  resetGrantForm();
  manageOpen.value = true;
  await loadDetail();
}

async function loadDetail() {
  if (!manageGroupId.value) return;
  detailLoading.value = true;
  actionError.value = "";
  try {
    detail.value = await usersApi.getAssetGroup(manageGroupId.value);
  } catch (loadError) {
    actionError.value = formatError(loadError);
  } finally {
    detailLoading.value = false;
  }
}

async function saveGroupInfo() {
  if (!detail.value) return;
  const name = nameDraft.value.trim();
  if (!name) return;
  saving.value = true;
  try {
    const updated = await usersApi.updateAssetGroup(detail.value.group.id, {
      name,
      description: descriptionDraft.value.trim(),
    });
    detail.value.group = {
      ...detail.value.group,
      name: updated.name,
      description: updated.description,
      updated_at: updated.updated_at,
    };
    toast(t("settings.identity.groupUpdated"));
    await loadGroups();
    emit("changed");
  } catch (updateError) {
    actionError.value = formatError(updateError);
  } finally {
    saving.value = false;
  }
}

async function addMember() {
  if (!detail.value || !memberDraft.value) return;
  try {
    const result = await usersApi.addAssetGroupMember(detail.value.group.id, memberDraft.value);
    if (!result.added) toast(t("settings.identity.groupMemberExists"));
    memberDraft.value = "";
    await Promise.all([loadDetail(), loadGroups()]);
    emit("changed");
  } catch (memberError) {
    actionError.value = formatError(memberError);
  }
}

async function removeMember(userId: string) {
  if (!detail.value) return;
  try {
    await usersApi.removeAssetGroupMember(detail.value.group.id, userId);
    await Promise.all([loadDetail(), loadGroups()]);
    emit("changed");
  } catch (memberError) {
    actionError.value = formatError(memberError);
  }
}

async function onConnectionChange() {
  grantForm.database_name = "";
  grantForm.schema_name = "";
  grantForm.table_name = "";
  databases.value = [];
  schemas.value = [];
  tables.value = [];
  if (!grantForm.connection_id) return;
  metaLoading.databases = true;
  try {
    const names = isMongo.value
      ? await api.mongoListDatabases(grantForm.connection_id)
      : (await api.listDatabases(grantForm.connection_id)).map((database) => database.name);
    databases.value = [...new Set(names)].sort((left, right) => left.localeCompare(right));
  } catch {
    // Free-text entry still works when metadata is unavailable.
  } finally {
    metaLoading.databases = false;
  }
}

async function onDatabaseChange() {
  grantForm.schema_name = "";
  grantForm.table_name = "";
  schemas.value = [];
  tables.value = [];
  if (!grantForm.connection_id || !grantForm.database_name || isMongo.value) return;
  metaLoading.schemas = true;
  try {
    schemas.value = (await api.listSchemas(grantForm.connection_id, grantForm.database_name)).sort((left, right) =>
      left.localeCompare(right),
    );
    if (!grantForm.schema_name && schemas.value.length === 1) grantForm.schema_name = schemas.value[0];
  } catch {
    // Free-text entry still works when metadata is unavailable.
  } finally {
    metaLoading.schemas = false;
  }
}

async function onSchemaChange() {
  grantForm.table_name = "";
  tables.value = [];
  if (!grantForm.connection_id || !grantForm.database_name) return;
  if (!isMongo.value && !grantForm.schema_name) return;
  metaLoading.tables = true;
  try {
    const names = isMongo.value
      ? (await api.mongoListCollections(grantForm.connection_id, grantForm.database_name)).map((collection) => collection.name)
      : (await api.listTables(grantForm.connection_id, grantForm.database_name, grantForm.schema_name)).map((table) => table.name);
    tables.value = [...new Set(names)].sort((left, right) => left.localeCompare(right));
  } catch {
    // Free-text entry still works when metadata is unavailable.
  } finally {
    metaLoading.tables = false;
  }
}

async function addGrant() {
  if (!detail.value || !canAddGrant.value) return;
  const expires = expiryForAdd();
  if (expires === undefined) {
    actionError.value = t("settings.identity.invalidGrant");
    return;
  }
  try {
    await usersApi.createGroupAssetGrant(detail.value.group.id, {
      role_code: grantForm.role_code,
      target_kind: grantForm.target_kind,
      connection_group_id: grantForm.target_kind === "connection_group" ? grantForm.connection_group_id : null,
      connection_id: grantForm.target_kind === "connection_group" ? null : grantForm.connection_id,
      database_name: needsDatabase.value ? grantForm.database_name.trim() : null,
      schema_name: needsSchema.value ? grantForm.schema_name.trim() : null,
      table_name: needsTable.value ? grantForm.table_name.trim() : null,
      name_pattern: needsTable.value ? grantForm.name_pattern : false,
      expires_at: expires,
      reason: grantForm.reason.trim(),
    });
    grantForm.reason = "";
    grantForm.expiry_mode = "never";
    grantForm.expires_at = "";
    toast(t("settings.identity.grantCreated"));
    await Promise.all([loadDetail(), loadGroups()]);
    emit("changed");
  } catch (grantError) {
    actionError.value = formatError(grantError);
    toast(actionError.value);
  }
}

async function removeGrant(grant: AssetGrant) {
  if (!detail.value) return;
  try {
    await usersApi.deleteGroupAssetGrant(detail.value.group.id, grant.id);
    await Promise.all([loadDetail(), loadGroups()]);
    emit("changed");
  } catch (grantError) {
    actionError.value = formatError(grantError);
  }
}

function requestDeleteGroup(group: AssetGroup) {
  deletingGroup.value = group;
}

async function confirmDeleteGroup() {
  if (!deletingGroup.value) return;
  deleting.value = true;
  try {
    await usersApi.deleteAssetGroup(deletingGroup.value.id);
    if (manageGroupId.value === deletingGroup.value.id) manageOpen.value = false;
    deletingGroup.value = null;
    toast(t("settings.identity.groupDeleted"));
    await loadGroups();
    emit("changed");
  } catch (deleteError) {
    toast(formatError(deleteError));
  } finally {
    deleting.value = false;
  }
}

onMounted(() => {
  void loadGroups();
});

async function openGroupById(groupId: string) {
  let group = groups.value.find((candidate) => candidate.id === groupId);
  if (!group) {
    await loadGroups();
    group = groups.value.find((candidate) => candidate.id === groupId);
  }
  if (group) await openManage(group);
}

defineExpose({ openGroupById });
</script>

<template>
  <div class="space-y-3">
    <div>
      <h3 class="text-base font-medium">{{ t("settings.identity.groupsTitle") }}</h3>
      <p class="text-sm text-muted-foreground">{{ t("settings.identity.groupsDescription") }}</p>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-sm text-destructive">{{ error }}</p>

    <div class="flex flex-wrap items-end gap-2 rounded-lg border border-border/60 p-3">
      <Input v-model="createDraft.name" class="h-8 w-52" :placeholder="t('settings.identity.accessGroupName')" />
      <Input v-model="createDraft.description" class="h-8 w-72" :placeholder="t('settings.identity.groupDescription')" />
      <Button size="sm" :disabled="saving || !createDraft.name.trim()" @click="createGroup">
        <Plus class="mr-1 h-3.5 w-3.5" />
        {{ t("settings.identity.createAccessGroup") }}
      </Button>
      <Button size="sm" variant="outline" :disabled="loading" @click="loadGroups">
        <RefreshCw :class="['h-3.5 w-3.5', loading ? 'animate-spin' : '']" />
      </Button>
    </div>

    <div class="overflow-hidden rounded-lg border border-border/60">
      <table class="w-full table-fixed text-sm">
        <thead class="bg-muted/40 text-left text-xs text-muted-foreground">
          <tr>
            <th class="px-3 py-2 font-medium">{{ t("settings.identity.accessGroupName") }}</th>
            <th class="w-28 px-3 py-2 font-medium">{{ t("settings.identity.groupMemberCount") }}</th>
            <th class="w-28 px-3 py-2 font-medium">{{ t("settings.identity.groupGrantCount") }}</th>
            <th class="w-48 px-3 py-2 text-right font-medium">{{ t("settings.identity.columnActions") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="loading">
            <td colspan="4" class="px-3 py-6 text-center text-muted-foreground">
              <LoaderCircle class="mx-auto h-4 w-4 animate-spin" />
            </td>
          </tr>
          <template v-else>
            <tr v-for="group in groups" :key="group.id" class="border-t border-border/40">
              <td class="px-3 py-2">
                <div class="truncate font-medium">{{ group.name }}</div>
                <div class="truncate text-xs text-muted-foreground">{{ group.description || "—" }}</div>
              </td>
              <td class="px-3 py-2">{{ group.member_count }}</td>
              <td class="px-3 py-2">{{ group.grant_count }}</td>
              <td class="px-3 py-2">
                <div class="flex justify-end gap-1">
                  <Button size="sm" variant="outline" class="h-7 px-1.5 text-xs" @click="openManage(group)">
                    <Pencil class="mr-1 h-3.5 w-3.5" />
                    {{ t("settings.identity.manageGroup") }}
                  </Button>
                  <Button size="sm" variant="outline" class="h-7 px-1.5 text-destructive" @click="requestDeleteGroup(group)">
                    <Trash2 class="h-3.5 w-3.5" />
                  </Button>
                </div>
              </td>
            </tr>
            <tr v-if="groups.length === 0">
              <td colspan="4" class="px-3 py-6 text-center text-muted-foreground">{{ t("settings.identity.groupsEmpty") }}</td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>

    <Dialog :open="manageOpen" @update:open="(value) => (manageOpen = value)">
      <DialogContent class="max-h-[calc(var(--dbx-viewport-height)-2rem)] w-full max-w-3xl overflow-y-auto">
        <DialogTitle class="text-base font-medium">{{ t("settings.identity.manageGroupTitle") }}</DialogTitle>
        <p v-if="actionError" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">
          {{ actionError }}
        </p>
        <div v-if="detailLoading" class="flex justify-center py-6">
          <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
        </div>
        <div v-else-if="detail" class="space-y-4">
          <section class="space-y-2 rounded-lg border border-border/60 p-3">
            <div class="text-sm font-medium">{{ t("settings.identity.groupDetails") }}</div>
            <div class="flex flex-wrap gap-2">
              <Input v-model="nameDraft" class="h-8 w-52" :placeholder="t('settings.identity.accessGroupName')" />
              <Input v-model="descriptionDraft" class="h-8 flex-1" :placeholder="t('settings.identity.groupDescription')" />
              <Button size="sm" :disabled="saving || !nameDraft.trim()" @click="saveGroupInfo">
                {{ t("settings.identity.saveGroupDetails") }}
              </Button>
            </div>
          </section>

          <section class="space-y-2 rounded-lg border border-border/60 p-3">
            <div class="flex items-center justify-between gap-2">
              <div>
                <div class="text-sm font-medium">{{ t("settings.identity.accessGroupMembers") }}</div>
                <p class="text-xs text-muted-foreground">{{ t("settings.identity.groupMembersHint") }}</p>
              </div>
              <Badge variant="outline">{{ detail.members.length }}</Badge>
            </div>
            <div class="flex flex-wrap gap-2">
              <select v-model="memberDraft" class="h-8 min-w-56 rounded-md border border-input bg-background px-2 text-sm">
                <option value="">{{ t("settings.identity.selectUser") }}</option>
                <option v-for="user in memberOptions" :key="user.id" :value="user.id">
                  {{ user.display_name || user.email }} ({{ user.email }})
                </option>
              </select>
              <Button size="sm" variant="outline" :disabled="!memberDraft" @click="addMember">
                <UserPlus class="mr-1 h-3.5 w-3.5" />
                {{ t("settings.identity.addMember") }}
              </Button>
            </div>
            <p v-if="detail.members.length === 0" class="text-xs text-muted-foreground">{{ t("settings.identity.groupNoMembers") }}</p>
            <div v-for="member in detail.members" :key="member.user_id" class="flex items-center justify-between gap-2 rounded-md border border-border/40 px-2 py-1.5 text-xs">
              <div class="min-w-0">
                <div class="truncate font-medium">{{ member.display_name || member.email || member.user_id }}</div>
                <div class="truncate text-muted-foreground">{{ member.email }}</div>
              </div>
              <Button size="sm" variant="outline" class="h-6 px-1.5 text-destructive" :title="t('settings.identity.removeMember')" @click="removeMember(member.user_id)">
                <X class="h-3 w-3" />
              </Button>
            </div>
          </section>

          <section class="space-y-2 rounded-lg border border-border/60 p-3">
            <div class="flex items-center justify-between gap-2">
              <div>
                <div class="text-sm font-medium">{{ t("settings.identity.assetGrantsTitle") }}</div>
                <p class="text-xs text-muted-foreground">{{ t("settings.identity.groupGrantsHint") }}</p>
              </div>
              <Badge variant="outline">{{ detail.grants.length }}</Badge>
            </div>
            <p v-if="detail.grants.length === 0" class="text-xs text-muted-foreground">{{ t("settings.identity.noGrants") }}</p>
            <div v-for="grant in detail.grants" :key="grant.id" class="flex flex-wrap items-center gap-2 rounded-md border border-border/40 px-2 py-1.5 text-xs">
              <Badge variant="outline">{{ roleLabel(grant.role_code) }}</Badge>
              <span class="min-w-0 flex-1 truncate" :title="targetLabel(grant)">{{ targetLabel(grant) }}</span>
              <span class="text-muted-foreground">{{ formatDate(grant.expires_at) }}</span>
              <Button size="sm" variant="outline" class="h-6 px-1.5 text-destructive" :title="t('settings.identity.removeGrant')" @click="removeGrant(grant)">
                <Trash2 class="h-3 w-3" />
              </Button>
            </div>

            <div class="space-y-2 rounded-md border border-dashed border-border/60 p-2">
              <div class="text-xs font-medium">{{ t("settings.identity.addGroupGrant") }}</div>
              <div class="flex flex-wrap gap-2">
                <select v-model="grantForm.role_code" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
                  <option v-for="role in assetRoles" :key="role.code" :value="role.code">{{ role.name }}</option>
                </select>
                <select v-model="grantForm.target_kind" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="onConnectionChange">
                  <option value="connection_group">{{ t("settings.identity.targetGroup") }}</option>
                  <option value="connection">{{ t("settings.identity.columnConnection") }}</option>
                  <option value="database">{{ t("settings.identity.columnDatabase") }}</option>
                  <option value="schema">{{ t("settings.identity.columnSchema") }}</option>
                  <option value="table">{{ t("settings.identity.targetTable") }}</option>
                </select>
                <select v-if="grantForm.target_kind === 'connection_group'" v-model="grantForm.connection_group_id" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
                  <option value="">{{ t("settings.identity.targetGroup") }}</option>
                  <option v-for="group in props.connectionGroups" :key="group.id" :value="group.id">{{ group.name }}</option>
                </select>
                <select v-else v-model="grantForm.connection_id" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="onConnectionChange">
                  <option value="">{{ t("settings.identity.selectConnection") }}</option>
                  <option v-for="connection in props.connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
                </select>
                <select v-if="needsDatabase" v-model="grantForm.database_name" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="onDatabaseChange">
                  <option value="">{{ t("settings.identity.selectDatabase") }}</option>
                  <option v-for="database in databases" :key="database" :value="database">{{ database }}</option>
                </select>
                <select v-if="needsSchema" v-model="grantForm.schema_name" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="onSchemaChange">
                  <option value="">{{ t("settings.identity.selectSchema") }}</option>
                  <option v-for="schema in schemas" :key="schema" :value="schema">{{ schema }}</option>
                </select>
                <select v-if="needsTable" v-model="grantForm.table_name" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
                  <option value="">{{ t("settings.identity.selectTable") }}</option>
                  <option v-for="table in tables" :key="table" :value="table">{{ table }}</option>
                </select>
              </div>
              <div class="flex flex-wrap items-center gap-2">
                <label v-if="needsTable" class="flex items-center gap-1 text-xs">
                  <input v-model="grantForm.name_pattern" type="checkbox" />
                  {{ t("settings.identity.usePattern") }}
                </label>
                <select v-model="grantForm.expiry_mode" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
                  <option value="never">{{ t("settings.identity.expiryNever") }}</option>
                  <option value="1d">{{ t("settings.identity.expiry1d") }}</option>
                  <option value="7d">{{ t("settings.identity.expiry7d") }}</option>
                  <option value="30d">{{ t("settings.identity.expiry30d") }}</option>
                  <option value="custom">{{ t("settings.identity.expiryCustom") }}</option>
                </select>
                <Input v-if="grantForm.expiry_mode === 'custom'" v-model="grantForm.expires_at" type="datetime-local" class="h-8 w-52" />
                <Input v-model="grantForm.reason" class="h-8 min-w-48 flex-1" :placeholder="t('settings.identity.grantReason')" />
                <Button size="sm" :disabled="!canAddGrant" @click="addGrant">{{ t("settings.identity.addGroupGrant") }}</Button>
              </div>
              <p class="text-[11px] text-muted-foreground">{{ t("settings.identity.manualEntryHint") }}</p>
            </div>
          </section>
        </div>
      </DialogContent>
    </Dialog>

    <Dialog :open="!!deletingGroup" @update:open="(value) => !value && (deletingGroup = null)">
      <DialogContent class="sm:max-w-md">
        <DialogTitle>{{ t("settings.identity.deleteGroupTitle") }}</DialogTitle>
        <p class="text-sm text-muted-foreground">
          {{ t("settings.identity.deleteGroupConfirm", { name: deletingGroup?.name ?? "" }) }}
        </p>
        <p class="text-xs text-muted-foreground">{{ t("settings.identity.deleteGroupImpact") }}</p>
        <div class="flex justify-end gap-2">
          <Button size="sm" variant="outline" @click="deletingGroup = null">{{ t("settings.identity.cancel") }}</Button>
          <Button size="sm" variant="destructive" :disabled="deleting" @click="confirmDeleteGroup">
            {{ t("settings.identity.removeGrant") }}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  </div>
</template>

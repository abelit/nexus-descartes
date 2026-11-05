<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Clock, LoaderCircle, Send, X } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import * as api from "@/lib/backend/api";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type { AccessRequest, AccessRequestOptions, AssetGrant } from "@/lib/backend/users";

const props = defineProps<{
  open: boolean;
  initialRole?: string;
  prefill?: {
    role?: string;
    connection_id?: string | null;
    database_name?: string | null;
    schema_name?: string | null;
    table_name?: string | null;
    justification?: string;
  } | null;
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
}>();

const { t } = useI18n();
const { toast } = useToast();

type TargetKind = AssetGrant["target_kind"];

const options = ref<AccessRequestOptions | null>(null);
const myRequests = ref<AccessRequest[]>([]);
const loading = ref(false);
const submitting = ref(false);
const error = ref("");
const formError = ref("");

const databases = ref<string[]>([]);
const schemas = ref<string[]>([]);
const tables = ref<string[]>([]);

const form = reactive({
  role_code: "",
  target_kind: "connection" as TargetKind,
  connection_group_id: "",
  connection_id: "",
  database_name: "",
  schema_name: "",
  table_name: "",
  name_pattern: false,
  duration_hours: 24,
  justification: "",
});

const DURATIONS = [1, 4, 8, 24, 72, 168, 720];

const selectedConnection = computed(() =>
  options.value?.connections.find((connection) => connection.id === form.connection_id),
);
const isMongo = computed(() => selectedConnection.value?.db_type === "mongodb");
const needsDatabase = computed(() => ["database", "schema", "table"].includes(form.target_kind));
const needsSchema = computed(() => ["schema", "table"].includes(form.target_kind) && !isMongo.value);
const needsTable = computed(() => form.target_kind === "table");
const selectedRole = computed(() => options.value?.roles.find((role) => role.code === form.role_code));

const canSubmit = computed(() => {
  if (!form.role_code || !form.justification.trim()) return false;
  if (form.target_kind === "connection_group") return !!form.connection_group_id;
  if (!form.connection_id) return false;
  if (needsDatabase.value && !form.database_name.trim()) return false;
  if (needsSchema.value && !form.schema_name.trim()) return false;
  if (needsTable.value && !form.table_name.trim()) return false;
  return form.duration_hours >= 1;
});

function resetForm() {
  const preferred = props.initialRole?.trim();
  form.role_code =
    (preferred && options.value?.roles.some((role) => role.code === preferred) ? preferred : undefined) ??
    options.value?.roles.find((role) => role.code === "viewer")?.code ??
    options.value?.roles[0]?.code ??
    "";
  form.target_kind = "connection";
  form.connection_group_id = "";
  form.connection_id = "";
  form.database_name = "";
  form.schema_name = "";
  form.table_name = "";
  form.name_pattern = false;
  form.duration_hours = 24;
  form.justification = "";
  databases.value = [];
  schemas.value = [];
  tables.value = [];
  const prefill = props.prefill;
  if (prefill) {
    if (prefill.role && options.value?.roles.some((role) => role.code === prefill.role)) {
      form.role_code = prefill.role;
    }
    form.connection_id = prefill.connection_id ?? "";
    form.database_name = prefill.database_name ?? "";
    form.schema_name = prefill.schema_name ?? "";
    form.table_name = prefill.table_name ?? "";
    form.target_kind = form.table_name ? "table" : form.database_name ? "database" : "connection";
    form.justification = prefill.justification ?? "";
  }
}

function requestTargetLabel(request: AccessRequest): string {
  if (request.target_kind === "connection_group") {
    return request.group_name || request.connection_group_id || t("settings.identity.targetGroup");
  }
  const connection = request.connection_name || request.connection_id || "—";
  if (request.target_kind === "connection") return connection;
  const base = `${connection} · ${request.database_name ?? ""}`;
  if (request.target_kind === "database") return base;
  if (request.target_kind === "schema") return `${base} / ${request.schema_name ?? ""}`;
  const table = request.name_pattern ? `${request.table_name ?? "*"} (${t("settings.accessRequests.pattern")})` : (request.table_name ?? "");
  return `${base} / ${request.schema_name ?? ""} / ${table}`;
}

function statusClass(status: AccessRequest["status"], expired: boolean): string {
  if (expired && status === "approved") return "border-amber-500/50 text-amber-600 dark:text-amber-400";
  switch (status) {
    case "approved":
      return "border-green-500/40 text-green-600 dark:text-green-400";
    case "rejected":
      return "border-destructive/50 text-destructive";
    case "cancelled":
      return "border-border text-muted-foreground";
    default:
      return "border-sky-500/50 text-sky-600 dark:text-sky-400";
  }
}

function statusLabel(status: AccessRequest["status"], expired: boolean): string {
  if (expired && status === "approved") return t("settings.accessRequests.statusExpired");
  return t(`settings.accessRequests.status_${status}`);
}

function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function durationLabel(hours: number): string {
  if (hours % 24 === 0) return t("settings.accessRequests.durationDays", { count: hours / 24 });
  return t("settings.accessRequests.durationHours", { count: hours });
}

async function loadOptions() {
  loading.value = true;
  error.value = "";
  try {
    options.value = await usersApi.accessRequestOptions();
    if (!options.value.roles.some((role) => role.code === form.role_code)) {
      resetForm();
    }
    await loadMine();
  } catch (loadError) {
    error.value = formatError(loadError);
  } finally {
    loading.value = false;
  }
}

async function loadMine() {
  try {
    myRequests.value = await usersApi.listAccessRequests({ scope: "mine", limit: 50 });
  } catch (loadError) {
    myRequests.value = [];
    error.value = formatError(loadError);
  }
}

async function onConnectionChange() {
  form.database_name = "";
  form.schema_name = "";
  form.table_name = "";
  databases.value = [];
  schemas.value = [];
  tables.value = [];
  if (!form.connection_id) return;
  try {
    const names = isMongo.value
      ? await api.mongoListDatabases(form.connection_id)
      : (await api.listDatabases(form.connection_id)).map((database) => database.name);
    databases.value = [...new Set(names)].sort((left, right) => left.localeCompare(right));
  } catch {
    // The requester may not have metadata access yet; manual entry still works.
  }
}

async function onDatabaseChange() {
  form.schema_name = "";
  form.table_name = "";
  schemas.value = [];
  tables.value = [];
  if (!form.connection_id || !form.database_name || isMongo.value) return;
  try {
    schemas.value = (await api.listSchemas(form.connection_id, form.database_name)).sort((left, right) =>
      left.localeCompare(right),
    );
  } catch {
    // Manual entry fallback.
  }
}

async function onSchemaChange() {
  form.table_name = "";
  tables.value = [];
  if (!form.connection_id || !form.database_name) return;
  if (!isMongo.value && !form.schema_name) return;
  try {
    const names = isMongo.value
      ? (await api.mongoListCollections(form.connection_id, form.database_name)).map((collection) => collection.name)
      : (await api.listTables(form.connection_id, form.database_name, form.schema_name)).map((table) => table.name);
    tables.value = [...new Set(names)].sort((left, right) => left.localeCompare(right));
  } catch {
    // Manual entry fallback.
  }
}

async function submit() {
  if (!canSubmit.value) return;
  submitting.value = true;
  formError.value = "";
  try {
    await usersApi.createAccessRequest({
      role_code: form.role_code,
      target_kind: form.target_kind,
      connection_group_id: form.target_kind === "connection_group" ? form.connection_group_id : null,
      connection_id: form.target_kind === "connection_group" ? null : form.connection_id,
      database_name: needsDatabase.value ? form.database_name.trim() : null,
      schema_name: needsSchema.value ? form.schema_name.trim() : null,
      table_name: needsTable.value ? form.table_name.trim() : null,
      name_pattern: needsTable.value ? form.name_pattern : false,
      duration_hours: form.duration_hours,
      justification: form.justification.trim(),
    });
    toast(t("settings.accessRequests.created"));
    resetForm();
    await loadMine();
  } catch (submitError) {
    formError.value = formatError(submitError);
  } finally {
    submitting.value = false;
  }
}

async function cancel(request: AccessRequest) {
  try {
    await usersApi.cancelAccessRequest(request.id);
    toast(t("settings.accessRequests.cancelled"));
    await loadMine();
  } catch (cancelError) {
    formError.value = formatError(cancelError);
  }
}

watch(
  () => props.open,
  (open) => {
    if (open) {
      formError.value = "";
      void loadOptions();
    }
  },
  { immediate: true },
);
</script>

<template>
  <Dialog :open="props.open" @update:open="(value) => emit('update:open', value)">
    <DialogContent class="max-h-[calc(var(--dbx-viewport-height)-2rem)] w-full max-w-3xl overflow-y-auto">
      <DialogTitle class="text-base font-medium">{{ t("settings.accessRequests.title") }}</DialogTitle>
      <p class="text-xs text-muted-foreground">{{ t("settings.accessRequests.description") }}</p>

      <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">{{ error }}</p>

      <div v-if="loading" class="flex justify-center py-6">
        <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
      </div>
      <div v-else class="space-y-4">
        <section class="space-y-2 rounded-lg border border-border/60 p-3">
          <div class="text-sm font-medium">{{ t("settings.accessRequests.newTitle") }}</div>
          <div class="grid gap-2 sm:grid-cols-2">
            <label class="space-y-1 text-xs">
              <span class="text-muted-foreground">{{ t("settings.accessRequests.role") }}</span>
              <select v-model="form.role_code" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
                <option v-for="role in options?.roles ?? []" :key="role.code" :value="role.code">{{ role.name }}</option>
              </select>
            </label>
            <label class="space-y-1 text-xs">
              <span class="text-muted-foreground">{{ t("settings.accessRequests.targetKind") }}</span>
              <select v-model="form.target_kind" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
                <option value="connection_group">{{ t("settings.identity.targetGroup") }}</option>
                <option value="connection">{{ t("settings.identity.targetConnection") }}</option>
                <option value="database">{{ t("settings.identity.targetDatabase") }}</option>
                <option value="schema">{{ t("settings.identity.targetSchema") }}</option>
                <option value="table">{{ t("settings.identity.targetTable") }}</option>
              </select>
            </label>
          </div>
          <div class="grid gap-2 sm:grid-cols-2">
            <label v-if="form.target_kind === 'connection_group'" class="space-y-1 text-xs">
              <span class="text-muted-foreground">{{ t("settings.identity.targetGroup") }}</span>
              <select v-model="form.connection_group_id" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
                <option value="">{{ t("settings.identity.targetGroup") }}</option>
                <option v-for="group in options?.connection_groups ?? []" :key="group.id" :value="group.id">{{ group.name }}</option>
              </select>
            </label>
            <label v-else class="space-y-1 text-xs">
              <span class="text-muted-foreground">{{ t("settings.identity.columnConnection") }}</span>
              <select v-model="form.connection_id" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" @change="onConnectionChange">
                <option value="">{{ t("settings.identity.selectConnection") }}</option>
                <option v-for="connection in options?.connections ?? []" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
              </select>
            </label>
            <label v-if="needsDatabase" class="space-y-1 text-xs">
              <span class="text-muted-foreground">{{ t("settings.identity.columnDatabase") }}</span>
              <Input v-model="form.database_name" class="h-8" list="access-request-databases" :placeholder="t('settings.identity.selectDatabase')" @change="onDatabaseChange" />
              <datalist id="access-request-databases">
                <option v-for="database in databases" :key="database" :value="database" />
              </datalist>
            </label>
            <label v-if="needsSchema" class="space-y-1 text-xs">
              <span class="text-muted-foreground">{{ t("settings.identity.columnSchema") }}</span>
              <Input v-model="form.schema_name" class="h-8" list="access-request-schemas" :placeholder="t('settings.identity.selectSchema')" @change="onSchemaChange" />
              <datalist id="access-request-schemas">
                <option v-for="schema in schemas" :key="schema" :value="schema" />
              </datalist>
            </label>
            <label v-if="needsTable" class="space-y-1 text-xs">
              <span class="text-muted-foreground">{{ t("settings.identity.targetTable") }}</span>
              <Input v-model="form.table_name" class="h-8" list="access-request-tables" :placeholder="t('settings.identity.selectTable')" />
              <datalist id="access-request-tables">
                <option v-for="table in tables" :key="table" :value="table" />
              </datalist>
            </label>
            <label class="space-y-1 text-xs">
              <span class="text-muted-foreground">{{ t("settings.accessRequests.duration") }}</span>
              <select v-model.number="form.duration_hours" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
                <option v-for="hours in DURATIONS" :key="hours" :value="hours">{{ durationLabel(hours) }}</option>
              </select>
            </label>
          </div>
          <label v-if="needsTable" class="flex items-center gap-1.5 text-xs">
            <input v-model="form.name_pattern" type="checkbox" />
            {{ t("settings.identity.usePattern") }}
          </label>
          <label class="block space-y-1 text-xs">
            <span class="text-muted-foreground">{{ t("settings.accessRequests.justification") }}</span>
            <textarea
              v-model="form.justification"
              rows="3"
              class="w-full rounded-md border border-input bg-background px-2 py-1.5 text-sm"
              :placeholder="t('settings.accessRequests.justificationPlaceholder')"
            />
          </label>
          <div v-if="selectedRole" class="text-[11px] text-muted-foreground">
            {{ t("settings.accessRequests.roleHint", { permissions: selectedRole.permissions.join(", ") }) }}
          </div>
          <p v-if="formError" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">{{ formError }}</p>
          <div class="flex justify-end">
            <Button size="sm" :disabled="submitting || !canSubmit" @click="submit">
              <LoaderCircle v-if="submitting" class="mr-1 h-3.5 w-3.5 animate-spin" />
              <Send v-else class="mr-1 h-3.5 w-3.5" />
              {{ t("settings.accessRequests.submit") }}
            </Button>
          </div>
        </section>

        <section class="space-y-2 rounded-lg border border-border/60 p-3">
          <div class="flex items-center justify-between">
            <div class="text-sm font-medium">{{ t("settings.accessRequests.mineTitle") }}</div>
            <Badge variant="outline">{{ myRequests.length }}</Badge>
          </div>
          <p v-if="myRequests.length === 0" class="text-xs text-muted-foreground">{{ t("settings.accessRequests.mineEmpty") }}</p>
          <div v-for="request in myRequests" :key="request.id" class="space-y-1 rounded-md border border-border/40 px-2 py-2 text-xs">
            <div class="flex flex-wrap items-center gap-2">
              <Badge variant="outline" :class="statusClass(request.status, request.expired)">{{ statusLabel(request.status, request.expired) }}</Badge>
              <Badge variant="outline">{{ request.role_name }}</Badge>
              <span class="min-w-0 flex-1 truncate font-medium" :title="requestTargetLabel(request)">{{ requestTargetLabel(request) }}</span>
              <span class="flex items-center gap-1 text-muted-foreground">
                <Clock class="h-3 w-3" />
                {{ durationLabel(request.duration_hours) }}
              </span>
              <Button v-if="request.status === 'pending'" size="sm" variant="outline" class="h-6 px-1.5 text-destructive" @click="cancel(request)">
                <X class="mr-1 h-3 w-3" />
                {{ t("settings.accessRequests.cancel") }}
              </Button>
            </div>
            <div class="text-muted-foreground">
              {{ t("settings.accessRequests.validUntil") }}: {{ formatDate(request.expires_at) }}
            </div>
            <div v-if="request.justification" class="truncate text-muted-foreground" :title="request.justification">{{ request.justification }}</div>
            <div v-if="request.status === 'pending'" class="text-muted-foreground">
              <template v-if="request.approver_names?.length">
                {{ t("settings.accessRequests.approver") }}: {{ request.approver_names.join(", ") }}
              </template>
              <template v-else>{{ t("settings.accessRequests.noApprover") }}</template>
            </div>
            <div v-else-if="request.decided_by_name" class="text-muted-foreground">
              {{ t("settings.accessRequests.approver") }}: {{ request.decided_by_name }}
            </div>
            <div v-if="request.decision_note" class="text-muted-foreground">
              {{ t("settings.accessRequests.decisionNote") }}: {{ request.decision_note }}
            </div>
          </div>
        </section>
      </div>
    </DialogContent>
  </Dialog>
</template>

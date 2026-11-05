<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import { LoaderCircle, Pencil, Plus, RefreshCw, Trash2, X } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type { DataPolicy, DataPolicyKind } from "@/lib/backend/users";

export interface DataPolicyConnectionOption {
  id: string;
  name: string;
  db_type: string;
}

const props = defineProps<{
  connections: DataPolicyConnectionOption[];
}>();

const { t } = useI18n();
const { toast } = useToast();

const policies = ref<DataPolicy[]>([]);
const loading = ref(false);
const saving = ref(false);
const error = ref("");
const editingId = ref("");
const formOpen = ref(false);

const form = reactive({
  name: "",
  kind: "mask" as DataPolicyKind,
  connection_id: "",
  database_name: "",
  schema_name: "",
  table_name: "",
  name_pattern: false,
  column_name: "",
  mask_type: "full" as "full" | "partial" | "email",
  replacement: "***",
  allowed_values: "",
  enabled: true,
});

const canSave = computed(
  () =>
    !!form.name.trim() &&
    !!form.connection_id &&
    !!form.table_name.trim() &&
    !!form.column_name.trim() &&
    (form.kind === "mask" || form.allowed_values.split(",").some((value) => value.trim())),
);

function connectionName(connectionId: string): string {
  return props.connections.find((connection) => connection.id === connectionId)?.name ?? connectionId;
}

function targetLabel(policy: DataPolicy): string {
  const connection = connectionName(policy.connection_id);
  const parts = [connection];
  if (policy.database_name) parts.push(policy.database_name);
  if (policy.schema_name) parts.push(policy.schema_name);
  parts.push(policy.table_name + (policy.name_pattern ? " (*)" : ""));
  return parts.join(" · ");
}

function kindLabel(kind: DataPolicyKind): string {
  return kind === "mask" ? t("settings.dataPolicies.kindMask") : t("settings.dataPolicies.kindRowFilter");
}

function detailLabel(policy: DataPolicy): string {
  if (policy.kind === "row_filter") return `${policy.column_name} ∈ [${policy.allowed_values.join(", ")}]`;
  return `${policy.column_name} → ${policy.mask_type}`;
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    policies.value = await usersApi.listDataPolicies();
  } catch (loadError) {
    error.value = formatError(loadError);
    policies.value = [];
  } finally {
    loading.value = false;
  }
}

function resetForm() {
  editingId.value = "";
  form.name = "";
  form.kind = "mask";
  form.connection_id = props.connections[0]?.id ?? "";
  form.database_name = "";
  form.schema_name = "";
  form.table_name = "";
  form.name_pattern = false;
  form.column_name = "";
  form.mask_type = "full";
  form.replacement = "***";
  form.allowed_values = "";
  form.enabled = true;
}

function startCreate() {
  resetForm();
  formOpen.value = true;
}

function startEdit(policy: DataPolicy) {
  editingId.value = policy.id;
  form.name = policy.name;
  form.kind = policy.kind;
  form.connection_id = policy.connection_id;
  form.database_name = policy.database_name ?? "";
  form.schema_name = policy.schema_name ?? "";
  form.table_name = policy.table_name;
  form.name_pattern = policy.name_pattern;
  form.column_name = policy.column_name;
  form.mask_type = policy.mask_type;
  form.replacement = policy.replacement;
  form.allowed_values = policy.allowed_values.join(", ");
  form.enabled = policy.enabled;
  formOpen.value = true;
}

async function save() {
  if (!canSave.value) return;
  saving.value = true;
  error.value = "";
  const input: usersApi.DataPolicyInput = {
    name: form.name.trim(),
    kind: form.kind,
    connection_id: form.connection_id,
    database_name: form.database_name.trim() || null,
    schema_name: form.schema_name.trim() || null,
    table_name: form.table_name.trim(),
    name_pattern: form.name_pattern,
    column_name: form.column_name.trim(),
    mask_type: form.mask_type,
    replacement: form.replacement.trim() || "***",
    allowed_values: form.allowed_values.split(",").map((value) => value.trim()).filter(Boolean),
    enabled: form.enabled,
  };
  try {
    if (editingId.value) {
      await usersApi.updateDataPolicy(editingId.value, input);
      toast(t("settings.dataPolicies.updated"));
    } else {
      await usersApi.createDataPolicy(input);
      toast(t("settings.dataPolicies.created"));
    }
    formOpen.value = false;
    await load();
  } catch (saveError) {
    error.value = formatError(saveError);
  } finally {
    saving.value = false;
  }
}

async function remove(policy: DataPolicy) {
  try {
    await usersApi.deleteDataPolicy(policy.id);
    toast(t("settings.dataPolicies.deleted"));
    await load();
  } catch (removeError) {
    error.value = formatError(removeError);
  }
}

onMounted(() => {
  resetForm();
  void load();
});
</script>

<template>
  <div class="space-y-3">
    <div class="flex flex-wrap items-start justify-between gap-2">
      <div>
        <h3 class="text-base font-medium">{{ t("settings.dataPolicies.title") }}</h3>
        <p class="text-sm text-muted-foreground">{{ t("settings.dataPolicies.description") }}</p>
      </div>
      <div class="flex items-center gap-2">
        <Button size="sm" :disabled="props.connections.length === 0" @click="startCreate">
          <Plus class="mr-1 h-3.5 w-3.5" />
          {{ t("settings.dataPolicies.create") }}
        </Button>
        <Button size="sm" variant="outline" :disabled="loading" @click="load">
          <RefreshCw :class="['h-3.5 w-3.5', loading ? 'animate-spin' : '']" />
        </Button>
      </div>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-sm text-destructive">{{ error }}</p>

    <div v-if="formOpen" class="space-y-3 rounded-lg border border-border/60 p-3">
      <div class="flex items-center justify-between">
        <div class="text-sm font-medium">
          {{ editingId ? t("settings.dataPolicies.editTitle") : t("settings.dataPolicies.createTitle") }}
        </div>
        <Button size="sm" variant="outline" class="h-7 px-1.5" @click="formOpen = false">
          <X class="h-3.5 w-3.5" />
        </Button>
      </div>
      <div class="grid gap-2 sm:grid-cols-3">
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.name") }}</span>
          <Input v-model="form.name" class="h-8" :placeholder="t('settings.dataPolicies.namePlaceholder')" />
        </label>
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.connection") }}</span>
          <select v-model="form.connection_id" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
            <option v-for="connection in props.connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
          </select>
        </label>
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.kind") }}</span>
          <select v-model="form.kind" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
            <option value="mask">{{ t("settings.dataPolicies.kindMask") }}</option>
            <option value="row_filter">{{ t("settings.dataPolicies.kindRowFilter") }}</option>
          </select>
        </label>
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.database") }}</span>
          <Input v-model="form.database_name" class="h-8" :placeholder="t('settings.dataPolicies.any')" />
        </label>
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.schema") }}</span>
          <Input v-model="form.schema_name" class="h-8" :placeholder="t('settings.dataPolicies.any')" />
        </label>
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.table") }}</span>
          <Input v-model="form.table_name" class="h-8" :placeholder="t('settings.dataPolicies.tablePlaceholder')" />
        </label>
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.column") }}</span>
          <Input v-model="form.column_name" class="h-8" :placeholder="t('settings.dataPolicies.columnPlaceholder')" />
        </label>
        <label v-if="form.kind === 'mask'" class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.maskType") }}</span>
          <select v-model="form.mask_type" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
            <option value="full">{{ t("settings.dataPolicies.maskFull") }}</option>
            <option value="partial">{{ t("settings.dataPolicies.maskPartial") }}</option>
            <option value="email">{{ t("settings.dataPolicies.maskEmail") }}</option>
          </select>
        </label>
        <label v-if="form.kind === 'mask'" class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.replacement") }}</span>
          <Input v-model="form.replacement" class="h-8" />
        </label>
        <label v-if="form.kind === 'row_filter'" class="space-y-1 text-xs sm:col-span-2">
          <span class="text-muted-foreground">{{ t("settings.dataPolicies.allowedValues") }}</span>
          <Input v-model="form.allowed_values" class="h-8" :placeholder="t('settings.dataPolicies.allowedValuesPlaceholder')" />
        </label>
      </div>
      <div class="flex flex-wrap items-center gap-3 text-xs">
        <label class="flex items-center gap-1.5">
          <input v-model="form.name_pattern" type="checkbox" />
          {{ t("settings.identity.usePattern") }}
        </label>
        <label class="flex items-center gap-1.5">
          <input v-model="form.enabled" type="checkbox" />
          {{ t("settings.dataPolicies.enabled") }}
        </label>
        <span class="text-muted-foreground">{{ t("settings.dataPolicies.hint") }}</span>
      </div>
      <div class="flex justify-end gap-2">
        <Button size="sm" variant="outline" @click="formOpen = false">{{ t("settings.dataPolicies.cancel") }}</Button>
        <Button size="sm" :disabled="saving || !canSave" @click="save">{{ t("settings.dataPolicies.save") }}</Button>
      </div>
    </div>

    <div v-if="loading" class="flex justify-center py-6">
      <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
    </div>
    <p v-else-if="policies.length === 0" class="rounded-lg border border-border/60 p-6 text-center text-sm text-muted-foreground">
      {{ t("settings.dataPolicies.empty") }}
    </p>
    <div v-else class="overflow-hidden rounded-lg border border-border/60">
      <table class="w-full table-fixed text-sm">
        <thead class="bg-muted/40 text-left text-xs text-muted-foreground">
          <tr>
            <th class="px-3 py-2 font-medium">{{ t("settings.dataPolicies.name") }}</th>
            <th class="w-28 px-3 py-2 font-medium">{{ t("settings.dataPolicies.kind") }}</th>
            <th class="px-3 py-2 font-medium">{{ t("settings.dataPolicies.target") }}</th>
            <th class="w-56 px-3 py-2 font-medium">{{ t("settings.dataPolicies.rule") }}</th>
            <th class="w-20 px-3 py-2 font-medium">{{ t("settings.dataPolicies.status") }}</th>
            <th class="w-24 px-3 py-2 text-right font-medium">{{ t("settings.identity.columnActions") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="policy in policies" :key="policy.id" class="border-t border-border/40">
            <td class="px-3 py-2">
              <div class="truncate font-medium">{{ policy.name }}</div>
            </td>
            <td class="px-3 py-2">
              <Badge variant="outline">{{ kindLabel(policy.kind) }}</Badge>
            </td>
            <td class="px-3 py-2">
              <div class="truncate" :title="targetLabel(policy)">{{ targetLabel(policy) }}</div>
            </td>
            <td class="px-3 py-2">
              <div class="truncate font-mono text-xs" :title="detailLabel(policy)">{{ detailLabel(policy) }}</div>
            </td>
            <td class="px-3 py-2">
              <Badge variant="outline" :class="policy.enabled ? 'border-green-500/40 text-green-600 dark:text-green-400' : 'text-muted-foreground'">
                {{ policy.enabled ? t("settings.dataPolicies.statusEnabled") : t("settings.dataPolicies.statusDisabled") }}
              </Badge>
            </td>
            <td class="px-3 py-2">
              <div class="flex justify-end gap-1">
                <Button size="sm" variant="outline" class="h-7 px-1.5" @click="startEdit(policy)">
                  <Pencil class="h-3.5 w-3.5" />
                </Button>
                <Button size="sm" variant="outline" class="h-7 px-1.5 text-destructive" @click="remove(policy)">
                  <Trash2 class="h-3.5 w-3.5" />
                </Button>
              </div>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

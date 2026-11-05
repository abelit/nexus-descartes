<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import { LoaderCircle, RefreshCw, Search } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type { AssetGrantInventoryItem, ConnectionGroup, LocalRole } from "@/lib/backend/users";

export interface InventoryConnectionOption {
  id: string;
  name: string;
}

const props = defineProps<{
  connections: InventoryConnectionOption[];
  groups: ConnectionGroup[];
  roles: LocalRole[];
}>();

const emit = defineEmits<{
  (event: "open-user-access", userId: string): void;
  (event: "open-group", groupId: string): void;
}>();

const { t } = useI18n();

const items = ref<AssetGrantInventoryItem[]>([]);
const loading = ref(false);
const error = ref("");
const filters = reactive({
  search: "",
  connection_id: "",
  role_code: "",
  status: "all" as "all" | "active" | "expiring" | "expired" | "stale",
  database: "",
  schema: "",
  table: "",
});

const visibleItems = computed(() => {
  const search = filters.search.trim().toLowerCase();
  return items.value.filter((item) => {
    if (!statusMatches(item)) return false;
    if (!search) return true;
    return [item.principal_name, item.user_email, item.user_display_name, item.connection_name, item.group_name, item.database_name, item.schema_name, item.table_name, item.role_name]
      .filter(Boolean)
      .some((value) => String(value).toLowerCase().includes(search));
  });
});

const counts = computed(() => {
  let active = 0;
  let expiring = 0;
  let expired = 0;
  let stale = 0;
  const now = Date.now();
  for (const item of items.value) {
    if (item.stale_reason) stale += 1;
    if (item.expired) {
      expired += 1;
      continue;
    }
    const expires = item.expires_at ? Date.parse(item.expires_at) : Number.NaN;
    if (!Number.isNaN(expires) && expires - now <= 7 * 24 * 60 * 60 * 1000) expiring += 1;
    else active += 1;
  }
  return { active, expiring, expired, stale, total: items.value.length };
});

function statusOf(item: AssetGrantInventoryItem): "active" | "expiring" | "expired" {
  if (item.expired) return "expired";
  if (!item.expires_at) return "active";
  const expires = Date.parse(item.expires_at);
  if (Number.isNaN(expires)) return "active";
  return expires - Date.now() <= 7 * 24 * 60 * 60 * 1000 ? "expiring" : "active";
}

function statusMatches(item: AssetGrantInventoryItem): boolean {
  if (filters.status === "all") return true;
  if (filters.status === "stale") return !!item.stale_reason;
  return statusOf(item) === filters.status;
}

function statusClass(item: AssetGrantInventoryItem): string {
  if (item.stale_reason) return "border-destructive/50 text-destructive";
  switch (statusOf(item)) {
    case "expired":
      return "border-destructive/50 text-destructive";
    case "expiring":
      return "border-amber-500/50 text-amber-600 dark:text-amber-400";
    default:
      return "border-green-500/40 text-green-600 dark:text-green-400";
  }
}

function statusLabel(item: AssetGrantInventoryItem): string {
  if (item.stale_reason) return t("settings.identity.inventoryStale");
  switch (statusOf(item)) {
    case "expired":
      return t("settings.identity.grantStatusExpired");
    case "expiring":
      return t("settings.identity.grantStatusExpiring");
    default:
      return t("settings.identity.grantStatusActive");
  }
}

function targetLabel(item: AssetGrantInventoryItem): string {
  if (item.target_kind === "connection_group") return item.group_name || item.connection_group_id || t("settings.identity.targetGroup");
  const connection = item.connection_name || item.connection_id || "—";
  if (item.target_kind === "connection") return connection;
  const base = `${connection} · ${item.database_name ?? ""}`;
  if (item.target_kind === "database") return base;
  if (item.target_kind === "schema") return `${base} / ${item.schema_name ?? ""}`;
  return `${base} / ${item.schema_name ?? ""} / ${item.table_name ?? ""}`;
}

function formatDate(value?: string | null): string {
  if (!value) return t("settings.identity.expiryNever");
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    items.value = await usersApi.listAssetGrantInventory({
      connection_id: filters.connection_id || undefined,
      role_code: filters.role_code || undefined,
      database: filters.database.trim() || undefined,
      schema: filters.schema.trim() || undefined,
      table: filters.table.trim() || undefined,
    });
  } catch (loadError) {
    error.value = formatError(loadError);
    items.value = [];
  } finally {
    loading.value = false;
  }
}

function refresh() {
  void load();
}

onMounted(() => {
  void load();
});
</script>

<template>
  <div class="space-y-3">
    <div>
      <h3 class="text-base font-medium">{{ t("settings.identity.inventoryTitle") }}</h3>
      <p class="text-sm text-muted-foreground">{{ t("settings.identity.inventoryDescription") }}</p>
    </div>

    <div class="grid grid-cols-2 gap-2 text-xs sm:grid-cols-4">
      <div class="rounded-md border border-border/60 p-2">
        <div class="text-muted-foreground">{{ t("settings.identity.grantStatusActive") }}</div>
        <div class="text-lg font-semibold">{{ counts.active + counts.expiring }}</div>
      </div>
      <div class="rounded-md border border-border/60 p-2">
        <div class="text-muted-foreground">{{ t("settings.identity.grantStatusExpiring") }}</div>
        <div class="text-lg font-semibold text-amber-600 dark:text-amber-400">{{ counts.expiring }}</div>
      </div>
      <div class="rounded-md border border-border/60 p-2">
        <div class="text-muted-foreground">{{ t("settings.identity.grantStatusExpired") }}</div>
        <div class="text-lg font-semibold text-destructive">{{ counts.expired }}</div>
      </div>
      <div class="rounded-md border border-border/60 p-2">
        <div class="text-muted-foreground">{{ t("settings.identity.inventoryStale") }}</div>
        <div class="text-lg font-semibold text-destructive">{{ counts.stale }}</div>
      </div>
    </div>

    <div class="flex flex-wrap items-center gap-2">
      <div class="relative">
        <Search class="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input v-model="filters.search" class="h-8 w-60 pl-7" :placeholder="t('settings.identity.inventorySearch')" />
      </div>
      <select v-model="filters.connection_id" class="h-8 max-w-48 rounded-md border border-input bg-background px-2 text-sm" @change="refresh">
        <option value="">{{ t("settings.identity.scopeGlobal") }}</option>
        <option v-for="connection in props.connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
      </select>
      <select v-model="filters.role_code" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="refresh">
        <option value="">{{ t("settings.identity.columnRole") }}</option>
        <option v-for="role in props.roles" :key="role.code" :value="role.code">{{ role.name }}</option>
      </select>
      <select v-model="filters.status" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
        <option value="all">{{ t("settings.identity.grantStatusAll") }}</option>
        <option value="active">{{ t("settings.identity.grantStatusActive") }}</option>
        <option value="expiring">{{ t("settings.identity.grantStatusExpiring") }}</option>
        <option value="expired">{{ t("settings.identity.grantStatusExpired") }}</option>
        <option value="stale">{{ t("settings.identity.inventoryStaleOnly") }}</option>
      </select>
      <Input v-model="filters.database" class="h-8 w-32" :placeholder="t('settings.identity.scopeDatabaseName')" @keyup.enter="refresh" />
      <Input v-model="filters.schema" class="h-8 w-28" :placeholder="t('settings.identity.scopeSchemaName')" @keyup.enter="refresh" />
      <Input v-model="filters.table" class="h-8 w-32" :placeholder="t('settings.identity.scopeTableName')" @keyup.enter="refresh" />
      <Button variant="outline" size="sm" class="gap-1.5" :disabled="loading" @click="refresh">
        <RefreshCw :class="['h-3.5 w-3.5', loading ? 'animate-spin' : '']" />
        {{ t("settings.audit.refresh") }}
      </Button>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-sm text-destructive">{{ error }}</p>

    <div class="overflow-hidden rounded-lg border border-border/60">
      <table class="w-full table-fixed text-sm">
        <thead class="bg-muted/40 text-left text-xs text-muted-foreground">
          <tr>
            <th class="px-3 py-2 font-medium">{{ t("settings.identity.inventoryUser") }}</th>
            <th class="w-36 px-3 py-2 font-medium">{{ t("settings.identity.columnRole") }}</th>
            <th class="px-3 py-2 font-medium">{{ t("settings.identity.inventoryTarget") }}</th>
            <th class="w-28 px-3 py-2 font-medium">{{ t("settings.identity.inventoryStatus") }}</th>
            <th class="w-44 px-3 py-2 font-medium">{{ t("settings.identity.inventoryExpires") }}</th>
            <th class="w-20 px-3 py-2 text-right font-medium">{{ t("settings.identity.columnActions") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="loading">
            <td colspan="6" class="px-3 py-6 text-center text-muted-foreground">
              <LoaderCircle class="mx-auto h-4 w-4 animate-spin" />
            </td>
          </tr>
          <template v-else>
            <tr v-for="item in visibleItems" :key="item.id" class="border-t border-border/40">
              <td class="px-3 py-2">
                <template v-if="item.principal_type === 'group'">
                  <div class="flex items-center gap-1.5">
                    <Badge variant="outline">{{ t("settings.identity.principalGroup") }}</Badge>
                    <span class="truncate font-medium">{{ item.principal_name }}</span>
                  </div>
                  <div class="truncate text-xs text-muted-foreground">
                    {{ t("settings.identity.groupMemberCount") }}: {{ item.member_count }}
                  </div>
                </template>
                <template v-else>
                  <div class="truncate font-medium">{{ item.user_display_name || item.user_email }}</div>
                  <div class="truncate text-xs text-muted-foreground">{{ item.user_email }}</div>
                </template>
              </td>
              <td class="px-3 py-2">
                <Badge variant="outline">{{ item.role_name }}</Badge>
              </td>
              <td class="px-3 py-2">
                <div class="truncate" :title="targetLabel(item)">{{ targetLabel(item) }}</div>
                <div v-if="item.stale_reason" class="truncate text-xs text-destructive" :title="item.stale_reason">{{ item.stale_reason }}</div>
                <div v-else-if="item.reason" class="truncate text-xs text-muted-foreground" :title="item.reason">{{ item.reason }}</div>
              </td>
              <td class="px-3 py-2">
                <Badge variant="outline" :class="statusClass(item)">{{ statusLabel(item) }}</Badge>
              </td>
              <td class="px-3 py-2 text-xs text-muted-foreground">
                <div class="truncate">{{ formatDate(item.expires_at) }}</div>
                <div v-if="item.granted_by" class="truncate text-[11px]" :title="item.granted_by">{{ t("settings.identity.inventoryGrantedBy") }}: {{ item.granted_by }}</div>
              </td>
              <td class="px-3 py-2 text-right">
                <Button
                  v-if="item.principal_type === 'group'"
                  size="sm"
                  variant="outline"
                  class="h-6 px-1.5 text-xs"
                  @click="emit('open-group', item.principal_id)"
                >
                  {{ t("settings.identity.manageGroup") }}
                </Button>
                <Button v-else size="sm" variant="outline" class="h-6 px-1.5 text-xs" @click="emit('open-user-access', item.user_id)">
                  {{ t("settings.identity.editUserAccess") }}
                </Button>
              </td>
            </tr>
          </template>
          <tr v-if="!loading && visibleItems.length === 0">
            <td colspan="6" class="px-3 py-6 text-center text-muted-foreground">{{ t("settings.identity.inventoryEmpty") }}</td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>

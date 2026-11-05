<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Check, LoaderCircle, RefreshCw, ShieldCheck, X } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type { AccessRequest, AccessRequestStatus } from "@/lib/backend/users";

const props = defineProps<{
  actorId?: string;
  readOnly?: boolean;
}>();

const { t } = useI18n();
const { toast } = useToast();

const requests = ref<AccessRequest[]>([]);
const loading = ref(false);
const error = ref("");
const statusFilter = ref<"pending" | "all" | "approved" | "rejected" | "cancelled">("pending");
const busyId = ref("");
const notes = reactive<Record<string, string>>({});

const visibleRequests = computed(() => requests.value);

function statusClass(request: AccessRequest): string {
  if (request.expired && request.status === "approved") return "border-amber-500/50 text-amber-600 dark:text-amber-400";
  switch (request.status) {
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

function statusLabel(request: AccessRequest): string {
  if (request.expired && request.status === "approved") return t("settings.accessRequests.statusExpired");
  return t(`settings.accessRequests.status_${request.status}`);
}

function durationLabel(hours: number): string {
  if (hours % 24 === 0) return t("settings.accessRequests.durationDays", { count: hours / 24 });
  return t("settings.accessRequests.durationHours", { count: hours });
}

function targetLabel(request: AccessRequest): string {
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

function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const status: AccessRequestStatus | undefined =
      statusFilter.value === "all" ? undefined : statusFilter.value;
    requests.value = await usersApi.listAccessRequests({ scope: "all", status, limit: 200 });
  } catch (loadError) {
    error.value = formatError(loadError);
    requests.value = [];
  } finally {
    loading.value = false;
  }
}

async function decide(request: AccessRequest, action: "approve" | "reject") {
  busyId.value = request.id;
  error.value = "";
  try {
    if (action === "approve") await usersApi.approveAccessRequest(request.id, notes[request.id] ?? "");
    else await usersApi.rejectAccessRequest(request.id, notes[request.id] ?? "");
    toast(action === "approve" ? t("settings.accessRequests.approved") : t("settings.accessRequests.rejected"));
    delete notes[request.id];
    await load();
  } catch (decideError) {
    error.value = formatError(decideError);
  } finally {
    busyId.value = "";
  }
}

onMounted(() => {
  void load();
});
</script>

<template>
  <div class="space-y-3">
    <div class="flex flex-wrap items-start justify-between gap-2">
      <div>
        <h3 class="text-base font-medium">{{ t("settings.accessRequests.adminTitle") }}</h3>
        <p class="text-sm text-muted-foreground">{{ t("settings.accessRequests.adminDescription") }}</p>
      </div>
      <div class="flex items-center gap-2">
        <select v-model="statusFilter" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="load">
          <option value="pending">{{ t("settings.accessRequests.filterPending") }}</option>
          <option value="all">{{ t("settings.accessRequests.filterAll") }}</option>
          <option value="approved">{{ t("settings.accessRequests.status_approved") }}</option>
          <option value="rejected">{{ t("settings.accessRequests.status_rejected") }}</option>
          <option value="cancelled">{{ t("settings.accessRequests.status_cancelled") }}</option>
        </select>
        <Button size="sm" variant="outline" :disabled="loading" @click="load">
          <RefreshCw :class="['h-3.5 w-3.5', loading ? 'animate-spin' : '']" />
        </Button>
      </div>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-sm text-destructive">{{ error }}</p>

    <div v-if="loading" class="flex justify-center py-6">
      <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
    </div>
    <p v-else-if="visibleRequests.length === 0" class="rounded-lg border border-border/60 p-6 text-center text-sm text-muted-foreground">
      {{ t("settings.accessRequests.adminEmpty") }}
    </p>
    <div v-else class="space-y-2">
      <div v-for="request in visibleRequests" :key="request.id" class="space-y-2 rounded-lg border border-border/60 p-3 text-sm">
        <div class="flex flex-wrap items-center gap-2">
          <Badge variant="outline" :class="statusClass(request)">{{ statusLabel(request) }}</Badge>
          <Badge variant="outline">{{ request.role_name }}</Badge>
          <span class="min-w-0 flex-1 truncate font-medium" :title="targetLabel(request)">{{ targetLabel(request) }}</span>
          <span class="text-xs text-muted-foreground">{{ durationLabel(request.duration_hours) }}</span>
        </div>
        <div class="text-xs text-muted-foreground">
          {{ t("settings.accessRequests.requester") }}: {{ request.requester_name }}
          <span v-if="request.requester_email">({{ request.requester_email }})</span>
          · {{ t("settings.accessRequests.requestedAt") }}: {{ formatDate(request.created_at) }}
          · {{ t("settings.accessRequests.validUntil") }}: {{ formatDate(request.expires_at) }}
        </div>
        <div class="rounded-md bg-muted/40 px-2 py-1.5 text-xs">
          <span class="font-medium">{{ t("settings.accessRequests.justification") }}:</span>
          {{ request.justification || "—" }}
        </div>
        <div v-if="request.decided_by_name || request.decision_note" class="text-xs text-muted-foreground">
          {{ t("settings.accessRequests.decidedBy") }}: {{ request.decided_by_name || request.decided_by || "—" }}
          <span v-if="request.decision_note"> · {{ request.decision_note }}</span>
        </div>
        <div v-if="request.status === 'pending'" class="text-xs text-muted-foreground">
          <template v-if="request.approver_names?.length">
            {{ t("settings.accessRequests.approver") }}: {{ request.approver_names.join(", ") }}
          </template>
          <template v-else>{{ t("settings.accessRequests.noApprover") }}</template>
        </div>
        <div v-if="request.status === 'pending' && !props.readOnly" class="flex flex-wrap items-center gap-2">
          <Input v-model="notes[request.id]" class="h-8 min-w-56 flex-1" :placeholder="t('settings.accessRequests.decisionPlaceholder')" />
          <Button
            size="sm"
            class="h-8"
            :disabled="busyId === request.id || request.requester_id === props.actorId"
            :title="request.requester_id === props.actorId ? t('settings.accessRequests.selfDecision') : ''"
            @click="decide(request, 'approve')"
          >
            <LoaderCircle v-if="busyId === request.id" class="mr-1 h-3.5 w-3.5 animate-spin" />
            <Check v-else class="mr-1 h-3.5 w-3.5" />
            {{ t("settings.accessRequests.approve") }}
          </Button>
          <Button
            size="sm"
            variant="outline"
            class="h-8 text-destructive"
            :disabled="busyId === request.id"
            @click="decide(request, 'reject')"
          >
            <X class="mr-1 h-3.5 w-3.5" />
            {{ t("settings.accessRequests.reject") }}
          </Button>
        </div>
        <div v-else-if="request.grant_id" class="flex items-center gap-1 text-xs text-muted-foreground">
          <ShieldCheck class="h-3.5 w-3.5" />
          {{ t("settings.accessRequests.grantCreated", { id: request.grant_id }) }}
        </div>
      </div>
    </div>
  </div>
</template>

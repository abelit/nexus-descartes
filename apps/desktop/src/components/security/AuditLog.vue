<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Download, KeyRound, LoaderCircle, RefreshCw, Search, ShieldAlert, ShieldCheck } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import SearchableSelect from "@/components/ui/searchable-select/SearchableSelect.vue";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as auditApi from "@/lib/backend/audit";
import type { AuditActorOption, AuditChainReport, AuditEvent, AuditRetention } from "@/lib/backend/audit";

const props = withDefaults(defineProps<{ sessionAuthorized?: boolean; canViewAll?: boolean; canExport?: boolean; canVerify?: boolean }>(), {
  canViewAll: true,
  canExport: true,
  canVerify: true,
});

const { t } = useI18n();
const { toast } = useToast();

const PAGE_SIZE = 100;

const token = ref(auditApi.auditAccessToken());
const tokenDraft = ref(auditApi.auditAccessToken());
const events = ref<AuditEvent[]>([]);
const nextCursor = ref<number | null>(null);
const eventsLoading = ref(false);
const loadingMore = ref(false);
const eventsError = ref("");
const selected = ref<AuditEvent | null>(null);

const filterActor = ref("");
const filterOperation = ref("");
const filterDecision = ref("");
const filterTarget = ref("");
const filterSql = ref("");
const rangeHours = ref("24");
const customFrom = ref("");
const customTo = ref("");
const actorOptions = ref<AuditActorOption[]>([]);
const actorsLoading = ref(false);

const actorIds = computed(() => actorOptions.value.map((actor) => actor.actor_id));
function actorLabel(id: string): string {
  const actor = actorOptions.value.find((option) => option.actor_id === id);
  return actor?.display_name || id;
}
async function loadActors() {
  if (!props.canViewAll || actorsLoading.value) return;
  actorsLoading.value = true;
  try {
    actorOptions.value = await auditApi.listAuditActors({ limit: 500 });
  } catch {
    // The filter is optional; keep the current options if the endpoint fails.
  } finally {
    actorsLoading.value = false;
  }
}
function selectActor(id: string) {
  filterActor.value = id;
  void refresh();
}

const verifying = ref(false);
const verifyReport = ref<AuditChainReport | null>(null);
const verifyError = ref("");

const retention = ref<AuditRetention | null>(null);
const retentionDays = ref("180");
const retentionLoading = ref(false);
const retentionError = ref("");
const savingRetention = ref(false);
const pruneOpen = ref(false);
const pruneReason = ref("");
const pruning = ref(false);

const OPERATIONS = ["query", "dml", "ddl", "transaction", "export", "import", "backup", "config", "connection", "auth", "policy", "approval", "admin"];
const DECISIONS = ["allowed", "denied", "warned", "approval_required", "blocked", "error"];
const RANGES = [
  { value: "1", labelKey: "settings.audit.rangeHour" },
  { value: "24", labelKey: "settings.audit.rangeDay" },
  { value: "168", labelKey: "settings.audit.rangeWeek" },
  { value: "0", labelKey: "settings.audit.rangeAll" },
  { value: "custom", labelKey: "settings.audit.rangeCustom" },
];

const chainHealthy = computed(() => verifyReport.value !== null && verifyReport.value.first_broken_seq === null);

function parseLocal(value: string): number | undefined {
  if (!value) return undefined;
  const parsed = new Date(value).getTime();
  return Number.isNaN(parsed) ? undefined : parsed;
}

function currentRange(): { from: number | undefined; to: number | undefined } {
  if (rangeHours.value === "custom") {
    return { from: parseLocal(customFrom.value), to: parseLocal(customTo.value) };
  }
  const hours = Number(rangeHours.value);
  return { from: hours > 0 ? Date.now() - hours * 60 * 60 * 1000 : undefined, to: undefined };
}

const customRangeError = computed(() => {
  if (rangeHours.value !== "custom") return "";
  const from = parseLocal(customFrom.value);
  const to = parseLocal(customTo.value);
  if (from !== undefined && to !== undefined && from > to) return t("settings.audit.customRangeInvalid");
  return "";
});

function filterParams() {
  const range = currentRange();
  return {
    actor_id: filterActor.value.trim() || undefined,
    operation: filterOperation.value || undefined,
    decision: filterDecision.value || undefined,
    target_contains: filterTarget.value.trim() || undefined,
    sql_contains: filterSql.value.trim() || undefined,
    from_ms: range.from,
    to_ms: range.to,
    limit: PAGE_SIZE,
  };
}

function applyToken() {
  auditApi.setAuditAccessToken(tokenDraft.value);
  token.value = auditApi.auditAccessToken();
  void refresh();
}

async function refresh() {
  if (customRangeError.value) {
    eventsError.value = customRangeError.value;
    return;
  }
  eventsLoading.value = true;
  eventsError.value = "";
  selected.value = null;
  try {
    const page = await auditApi.listAuditEvents(filterParams());
    events.value = page.events;
    nextCursor.value = page.next_cursor ?? null;
  } catch (error) {
    eventsError.value = formatError(error);
    events.value = [];
    nextCursor.value = null;
  } finally {
    eventsLoading.value = false;
  }
}

async function loadMore() {
  if (nextCursor.value === null) return;
  loadingMore.value = true;
  try {
    const page = await auditApi.listAuditEvents({ ...filterParams(), cursor_seq: nextCursor.value });
    events.value = [...events.value, ...page.events];
    nextCursor.value = page.next_cursor ?? null;
  } catch (error) {
    toast(formatError(error));
  } finally {
    loadingMore.value = false;
  }
}

async function verifyChain() {
  verifying.value = true;
  verifyError.value = "";
  try {
    verifyReport.value = await auditApi.verifyAuditChain();
  } catch (error) {
    verifyReport.value = null;
    verifyError.value = formatError(error);
  } finally {
    verifying.value = false;
  }
}

async function exportEvents(format: "jsonl" | "csv") {
  if (customRangeError.value) {
    toast(customRangeError.value);
    return;
  }
  try {
    const params = filterParams();
    const blob = await auditApi.downloadAuditExport(format, {
      actor_id: params.actor_id,
      operation: params.operation,
      decision: params.decision,
      target_contains: params.target_contains,
      sql_contains: params.sql_contains,
      from_ms: params.from_ms,
      to_ms: params.to_ms,
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `audit-events.${format}`;
    anchor.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    toast(formatError(error));
  }
}

function formatTime(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function decisionClass(decision: string): string {
  switch (decision) {
    case "blocked":
    case "denied":
      return "border-destructive/50 text-destructive";
    case "approval_required":
    case "warned":
      return "border-amber-500/50 text-amber-600 dark:text-amber-400";
    default:
      return "border-border text-muted-foreground";
  }
}

function details(event: AuditEvent): string {
  if (!event.details_json) return "";
  try {
    return JSON.stringify(JSON.parse(event.details_json), null, 2);
  } catch {
    return event.details_json;
  }
}

async function loadRetention() {
  retentionLoading.value = true;
  retentionError.value = "";
  try {
    retention.value = await auditApi.getAuditRetention();
    retentionDays.value = String(retention.value.days);
  } catch (error) {
    retentionError.value = formatError(error);
    retention.value = null;
  } finally {
    retentionLoading.value = false;
  }
}

async function saveRetention() {
  const days = Number(retentionDays.value);
  if (!Number.isFinite(days) || days < 0 || days > 36500 || !Number.isInteger(days)) {
    retentionError.value = t("settings.audit.retentionInvalid");
    return;
  }
  savingRetention.value = true;
  retentionError.value = "";
  try {
    retention.value = await auditApi.updateAuditRetention(days);
    retentionDays.value = String(retention.value.days);
    toast(t("settings.audit.retentionSaved"));
  } catch (error) {
    retentionError.value = formatError(error);
    toast(retentionError.value);
  } finally {
    savingRetention.value = false;
  }
}

async function pruneRetention() {
  const upTo = retention.value?.prunable_up_to_seq;
  if (!upTo) return;
  pruning.value = true;
  retentionError.value = "";
  try {
    const result = await auditApi.pruneAuditEvents(upTo, pruneReason.value.trim());
    toast(t("settings.audit.pruned", { count: result.deleted, seq: result.up_to_seq }));
    pruneOpen.value = false;
    pruneReason.value = "";
    await Promise.all([loadRetention(), refresh()]);
  } catch (error) {
    retentionError.value = formatError(error);
    toast(retentionError.value);
  } finally {
    pruning.value = false;
  }
}

onMounted(() => {
  void refresh();
  if (props.canViewAll) {
    void loadActors();
    void loadRetention();
  }
});
</script>

<template>
  <div class="space-y-4">
    <div class="flex flex-col gap-1">
      <h3 class="text-base font-medium">{{ t("settings.audit.title") }}</h3>
      <p class="text-sm text-muted-foreground">{{ t("settings.audit.description") }}</p>
    </div>

    <div v-if="props.canVerify" class="space-y-2 rounded-lg border border-border/60 p-3">
      <div class="flex items-center gap-2">
        <div class="text-sm font-medium">{{ t("settings.audit.retentionTitle") }}</div>
        <LoaderCircle v-if="retentionLoading" class="h-3.5 w-3.5 animate-spin text-muted-foreground" />
      </div>
      <p class="text-xs text-muted-foreground">{{ t("settings.audit.retentionHint") }}</p>
      <div class="flex flex-wrap items-center gap-2">
        <Input v-model="retentionDays" type="number" min="0" max="36500" class="h-8 w-24" :aria-label="t('settings.audit.retentionDays')" />
        <span class="text-xs text-muted-foreground">{{ t("settings.audit.retentionDays") }}</span>
        <Button size="sm" :disabled="savingRetention" @click="saveRetention">
          <LoaderCircle v-if="savingRetention" class="mr-1 h-3.5 w-3.5 animate-spin" />
          {{ t("settings.audit.retentionSave") }}
        </Button>
        <Button
          v-if="retention?.prunable_up_to_seq"
          size="sm"
          variant="destructive"
          :disabled="!retention.allow_prune || pruning"
          :title="retention.allow_prune ? '' : t('settings.audit.pruneDisabled')"
          @click="pruneReason = ''; pruneOpen = true"
        >
          {{ t("settings.audit.pruneButton", { seq: retention.prunable_up_to_seq }) }}
        </Button>
      </div>
      <p v-if="retentionError" class="text-xs text-destructive">{{ retentionError }}</p>
      <div v-if="retention" class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
        <span>{{ t("settings.audit.retentionOldest", { days: retention.oldest_age_days ?? "—" }) }}</span>
        <span>{{ t("settings.audit.retentionHead", { seq: retention.head_seq }) }}</span>
        <span>{{ t("settings.audit.retentionCheckpoint", { seq: retention.latest_checkpoint_seq ?? "—" }) }}</span>
        <span>{{ t("settings.audit.retentionExported", { seq: retention.exported_seq }) }}</span>
        <span v-if="retention.floor_seq != null">{{ t("settings.audit.retentionFloor", { seq: retention.floor_seq }) }}</span>
        <span v-if="!retention.allow_prune">{{ t("settings.audit.pruneDisabled") }}</span>
      </div>
    </div>

    <div v-if="!props.sessionAuthorized" class="space-y-2 rounded-lg border border-border/60 p-3">
      <div class="flex items-center gap-2 text-sm font-medium">
        <KeyRound class="h-4 w-4" />
        {{ t("settings.audit.accessToken") }}
      </div>
      <p class="text-xs text-muted-foreground">{{ t("settings.audit.accessTokenHint") }}</p>
      <div class="flex gap-2">
        <Input v-model="tokenDraft" type="password" class="h-8" :placeholder="t('settings.audit.accessTokenPlaceholder')" @keyup.enter="applyToken" />
        <Button variant="outline" size="sm" @click="applyToken">{{ t("settings.audit.saveToken") }}</Button>
      </div>
      <p v-if="!token" class="text-xs text-muted-foreground">{{ t("settings.audit.loopbackHint") }}</p>
    </div>

    <div class="flex flex-wrap items-center gap-2">
      <SearchableSelect
        v-if="props.canViewAll"
        :model-value="filterActor"
        :options="actorIds"
        :placeholder="t('settings.audit.filterActor')"
        :search-placeholder="t('settings.audit.filterActor')"
        :empty-text="t('grid.noSearchResults')"
        :loading="actorsLoading"
        :display-name="actorLabel"
        clearable
        trigger-class="h-8 w-48 justify-between"
        @update:model-value="selectActor"
        @update:open="(open) => open && loadActors()"
      />
      <select v-model="filterOperation" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
        <option value="">{{ t("settings.audit.filterOperationAll") }}</option>
        <option v-for="operation in OPERATIONS" :key="operation" :value="operation">{{ operation }}</option>
      </select>
      <select v-model="filterDecision" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
        <option value="">{{ t("settings.audit.filterDecisionAll") }}</option>
        <option v-for="decision in DECISIONS" :key="decision" :value="decision">{{ decision }}</option>
      </select>
      <select v-model="rangeHours" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
        <option v-for="range in RANGES" :key="range.value" :value="range.value">{{ t(range.labelKey) }}</option>
      </select>
      <template v-if="rangeHours === 'custom'">
        <Input v-model="customFrom" type="datetime-local" class="h-8 w-48" :aria-label="t('settings.audit.rangeFrom')" />
        <span class="text-xs text-muted-foreground">→</span>
        <Input v-model="customTo" type="datetime-local" class="h-8 w-48" :aria-label="t('settings.audit.rangeTo')" />
      </template>
      <div class="relative">
        <Search class="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input v-model="filterTarget" class="h-8 w-48 pl-7" :placeholder="t('settings.audit.filterTarget')" @keyup.enter="refresh" />
      </div>
      <div class="relative">
        <Search class="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input v-model="filterSql" class="h-8 w-56 pl-7" :placeholder="t('settings.audit.filterSql')" @keyup.enter="refresh" />
      </div>
      <Button variant="outline" size="sm" class="gap-1.5" :disabled="eventsLoading" @click="refresh">
        <RefreshCw :class="['h-3.5 w-3.5', eventsLoading ? 'animate-spin' : '']" />
        {{ t("settings.audit.refresh") }}
      </Button>
      <Button v-if="props.canExport" variant="outline" size="sm" class="gap-1.5" @click="exportEvents('jsonl')">
        <Download class="h-3.5 w-3.5" />
        JSONL
      </Button>
      <Button v-if="props.canExport" variant="outline" size="sm" class="gap-1.5" @click="exportEvents('csv')">
        <Download class="h-3.5 w-3.5" />
        CSV
      </Button>
      <Button v-if="props.canVerify" variant="outline" size="sm" class="gap-1.5" :disabled="verifying" @click="verifyChain">
        <LoaderCircle v-if="verifying" class="h-3.5 w-3.5 animate-spin" />
        <ShieldCheck v-else class="h-3.5 w-3.5" />
        {{ t("settings.audit.verify") }}
      </Button>
    </div>

    <p v-if="eventsError" class="text-sm text-destructive">{{ eventsError }}</p>
    <p v-if="verifyError" class="text-sm text-destructive">{{ verifyError }}</p>

    <div v-if="verifyReport" class="flex items-start gap-2 rounded-md border p-3 text-sm" :class="chainHealthy ? 'border-green-500/40 text-green-600 dark:text-green-400' : 'border-destructive/50 text-destructive'">
      <ShieldCheck v-if="chainHealthy" class="mt-0.5 h-4 w-4 shrink-0" />
      <ShieldAlert v-else class="mt-0.5 h-4 w-4 shrink-0" />
      <span v-if="chainHealthy">{{ t("settings.audit.verifyOk", { checked: verifyReport.checked, seq: verifyReport.head_seq }) }}</span>
      <span v-else>{{ t("settings.audit.verifyBroken", { seq: verifyReport.first_broken_seq ?? verifyReport.head_seq }) }}</span>
    </div>

    <div class="overflow-hidden rounded-lg border border-border/60">
      <table class="w-full table-fixed text-sm">
        <thead class="bg-muted/40 text-left text-xs text-muted-foreground">
          <tr>
            <th class="w-16 px-3 py-2 font-medium">#</th>
            <th class="w-44 px-3 py-2 font-medium">{{ t("settings.audit.columnTime") }}</th>
            <th class="w-40 px-3 py-2 font-medium">{{ t("settings.audit.columnActor") }}</th>
            <th class="w-28 px-3 py-2 font-medium">{{ t("settings.audit.columnOperation") }}</th>
            <th class="w-28 px-3 py-2 font-medium">{{ t("settings.audit.columnDecision") }}</th>
            <th class="px-3 py-2 font-medium">{{ t("settings.audit.columnTarget") }}</th>
            <th class="w-20 px-3 py-2 text-right font-medium">{{ t("settings.audit.columnDuration") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="eventsLoading">
            <td colspan="7" class="px-3 py-6 text-center text-muted-foreground">
              <LoaderCircle class="mx-auto h-4 w-4 animate-spin" />
            </td>
          </tr>
          <template v-else>
            <tr
              v-for="event in events"
              :key="event.event_id"
              class="cursor-pointer border-t border-border/40 hover:bg-muted/30 focus-visible:bg-muted/40 focus-visible:outline-none"
              :class="selected?.event_id === event.event_id ? 'bg-muted/40' : ''"
              tabindex="0"
              @click="selected = event"
              @keydown.enter.prevent="selected = event"
              @keydown.space.prevent="selected = event"
            >
              <td class="px-3 py-2 tabular-nums text-muted-foreground">{{ event.seq }}</td>
              <td class="truncate px-3 py-2">{{ formatTime(event.occurred_at) }}</td>
              <td class="truncate px-3 py-2" :title="event.actor.id">{{ event.actor.display_name || event.actor.id }}</td>
              <td class="px-3 py-2">{{ event.operation }}</td>
              <td class="px-3 py-2">
                <Badge variant="outline" :class="decisionClass(event.decision)">{{ event.decision }}</Badge>
              </td>
              <td class="truncate px-3 py-2 text-muted-foreground">
                {{ [event.connection_name || event.connection_id, event.database, event.table_name].filter(Boolean).join(" / ") || "—" }}
              </td>
              <td class="px-3 py-2 text-right tabular-nums text-muted-foreground">{{ event.duration_ms != null ? `${event.duration_ms} ms` : "—" }}</td>
            </tr>
          </template>
          <tr v-if="!eventsLoading && events.length === 0">
            <td colspan="7" class="px-3 py-6 text-center text-muted-foreground">{{ t("settings.audit.empty") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="nextCursor !== null" class="flex justify-center">
      <Button variant="outline" size="sm" :disabled="loadingMore" @click="loadMore">
        <LoaderCircle v-if="loadingMore" class="mr-1.5 h-3.5 w-3.5 animate-spin" />
        {{ t("settings.audit.loadMore") }}
      </Button>
    </div>

    <Dialog :open="!!selected" @update:open="(value) => !value && (selected = null)">
      <DialogContent
        class="ml-auto flex h-[calc(var(--dbx-viewport-height)-1rem)] w-full max-w-2xl flex-col gap-0 overflow-hidden rounded-xl p-0 max-h-none"
        portal-class="place-items-stretch p-2"
      >
        <template v-if="selected">
          <div class="shrink-0 space-y-1 border-b border-border px-4 py-3 pr-12">
            <div class="flex flex-wrap items-center gap-2">
              <DialogTitle class="text-base font-medium">{{ t("settings.audit.eventDetail") }} #{{ selected.seq }}</DialogTitle>
              <Badge variant="outline">{{ selected.source }}</Badge>
              <Badge variant="outline" :class="decisionClass(selected.decision)">{{ selected.decision }}</Badge>
              <Badge variant="outline">{{ selected.outcome }}</Badge>
              <Badge v-if="selected.risk_level" variant="outline">{{ selected.risk_level }}</Badge>
              <Badge v-if="!selected.actor_verified" variant="outline">{{ t("settings.audit.unverifiedActor") }}</Badge>
            </div>
            <div class="truncate font-mono text-xs text-muted-foreground">{{ selected.event_id }}</div>
          </div>
          <div class="min-h-0 flex-1 space-y-3 overflow-y-auto px-4 py-3 text-sm">
            <div class="grid gap-x-4 gap-y-1.5 text-xs text-muted-foreground sm:grid-cols-2">
              <span>{{ t("settings.audit.columnTime") }}: {{ formatTime(selected.occurred_at) }}</span>
              <span>{{ t("settings.audit.columnActor") }}: {{ selected.actor.display_name || selected.actor.id }}<template v-if="selected.actor.display_name && selected.actor.display_name !== selected.actor.id"> ({{ selected.actor.id }})</template> · {{ selected.actor.kind }}</span>
              <span>{{ t("settings.audit.clientIp") }}: {{ selected.client_ip || "—" }}</span>
              <span v-if="selected.user_agent">{{ t("settings.audit.userAgent") }}: {{ selected.user_agent }}</span>
              <span>{{ t("settings.audit.requestId") }}: {{ selected.request_id || "—" }}</span>
              <span v-if="selected.execution_id">{{ t("settings.audit.execution") }}: {{ selected.execution_id }}</span>
              <span v-if="selected.statement_index != null">{{ t("settings.audit.statementIndex") }}: {{ selected.statement_index }}</span>
              <span v-if="selected.affected_rows != null">{{ t("settings.audit.affectedRows") }}: {{ selected.affected_rows }}</span>
              <span v-if="selected.redaction_mode">{{ t("settings.audit.retention") }}: {{ selected.redaction_mode }}</span>
              <span>{{ t("settings.audit.columnTarget") }}: {{ [selected.connection_name || selected.connection_id, selected.database, selected.schema_name, selected.table_name].filter(Boolean).join(" / ") || "—" }}</span>
            </div>
            <div v-if="selected.sql_text" class="space-y-1">
              <div class="text-xs font-medium text-muted-foreground">{{ t("settings.audit.sql") }}</div>
              <pre class="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted/40 p-2 font-mono text-xs">{{ selected.sql_text }}</pre>
            </div>
            <div v-else-if="selected.sql_digest" class="space-y-1">
              <div class="text-xs font-medium text-muted-foreground">{{ t("settings.audit.digestOnly") }}</div>
              <pre class="overflow-auto rounded-md bg-muted/40 p-2 font-mono text-xs">{{ selected.sql_digest }}</pre>
            </div>
            <div v-if="selected.error_message" class="space-y-1">
              <div class="text-xs font-medium text-muted-foreground">{{ t("settings.audit.error") }}</div>
              <pre class="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-md bg-destructive/10 p-2 font-mono text-xs">{{ selected.error_message }}</pre>
            </div>
            <div v-if="selected.details_json" class="space-y-1">
              <div class="text-xs font-medium text-muted-foreground">{{ t("settings.audit.details") }}</div>
              <pre class="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted/40 p-2 font-mono text-xs">{{ details(selected) }}</pre>
            </div>
          </div>
        </template>
      </DialogContent>
    </Dialog>

    <Dialog :open="pruneOpen" @update:open="(value) => !value && (pruneOpen = false)">
      <DialogContent class="sm:max-w-md">
        <DialogTitle>{{ t("settings.audit.pruneTitle") }}</DialogTitle>
        <p class="text-sm text-muted-foreground">
          {{ t("settings.audit.pruneConfirm", { seq: retention?.prunable_up_to_seq ?? 0, days: retention?.days ?? 0 }) }}
        </p>
        <Input v-model="pruneReason" class="h-8" :placeholder="t('settings.audit.pruneReason')" />
        <p class="text-xs text-muted-foreground">{{ t("settings.audit.pruneHint") }}</p>
        <div class="flex justify-end gap-2">
          <Button variant="outline" size="sm" @click="pruneOpen = false">{{ t("settings.identity.cancel") }}</Button>
          <Button variant="destructive" size="sm" :disabled="pruning || !pruneReason.trim()" @click="pruneRetention">
            <LoaderCircle v-if="pruning" class="mr-1 h-3.5 w-3.5 animate-spin" />
            {{ t("settings.audit.pruneConfirmButton") }}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  </div>
</template>

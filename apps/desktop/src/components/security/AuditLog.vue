<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Download, KeyRound, LoaderCircle, RefreshCw, Search, ShieldAlert, ShieldCheck } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as auditApi from "@/lib/backend/audit";
import type { AuditChainReport, AuditEvent } from "@/lib/backend/audit";

const props = defineProps<{ sessionAuthorized?: boolean }>();

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
const filterSql = ref("");
const rangeHours = ref("24");

const verifying = ref(false);
const verifyReport = ref<AuditChainReport | null>(null);
const verifyError = ref("");

const OPERATIONS = ["query", "dml", "ddl", "transaction", "export", "import", "backup", "config", "connection", "auth", "policy", "approval", "admin"];
const DECISIONS = ["allowed", "denied", "warned", "approval_required", "blocked", "error"];
const RANGES = [
  { value: "1", labelKey: "settings.audit.rangeHour" },
  { value: "24", labelKey: "settings.audit.rangeDay" },
  { value: "168", labelKey: "settings.audit.rangeWeek" },
  { value: "0", labelKey: "settings.audit.rangeAll" },
];

const chainHealthy = computed(() => verifyReport.value !== null && verifyReport.value.first_broken_seq === null);

function currentFromMs(): number | undefined {
  const hours = Number(rangeHours.value);
  return hours > 0 ? Date.now() - hours * 60 * 60 * 1000 : undefined;
}

function filterParams() {
  return {
    actor_id: filterActor.value.trim() || undefined,
    operation: filterOperation.value || undefined,
    decision: filterDecision.value || undefined,
    sql_contains: filterSql.value.trim() || undefined,
    from_ms: currentFromMs(),
    limit: PAGE_SIZE,
  };
}

function applyToken() {
  auditApi.setAuditAccessToken(tokenDraft.value);
  token.value = auditApi.auditAccessToken();
  void refresh();
}

async function refresh() {
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
  try {
    const blob = await auditApi.downloadAuditExport(format, {
      actor_id: filterParams().actor_id,
      operation: filterParams().operation,
      decision: filterParams().decision,
      sql_contains: filterParams().sql_contains,
      from_ms: filterParams().from_ms,
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

onMounted(() => {
  void refresh();
});
</script>

<template>
  <div class="space-y-4">
    <div class="flex flex-col gap-1">
      <h3 class="text-base font-medium">{{ t("settings.audit.title") }}</h3>
      <p class="text-sm text-muted-foreground">{{ t("settings.audit.description") }}</p>
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
      <Input v-model="filterActor" class="h-8 w-40" :placeholder="t('settings.audit.filterActor')" @keyup.enter="refresh" />
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
      <div class="relative">
        <Search class="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
        <Input v-model="filterSql" class="h-8 w-56 pl-7" :placeholder="t('settings.audit.filterSql')" @keyup.enter="refresh" />
      </div>
      <Button variant="outline" size="sm" class="gap-1.5" :disabled="eventsLoading" @click="refresh">
        <RefreshCw :class="['h-3.5 w-3.5', eventsLoading ? 'animate-spin' : '']" />
        {{ t("settings.audit.refresh") }}
      </Button>
      <Button variant="outline" size="sm" class="gap-1.5" @click="exportEvents('jsonl')">
        <Download class="h-3.5 w-3.5" />
        JSONL
      </Button>
      <Button variant="outline" size="sm" class="gap-1.5" @click="exportEvents('csv')">
        <Download class="h-3.5 w-3.5" />
        CSV
      </Button>
      <Button variant="outline" size="sm" class="gap-1.5" :disabled="verifying" @click="verifyChain">
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
            <tr v-for="event in events" :key="event.event_id" class="cursor-pointer border-t border-border/40 hover:bg-muted/30" :class="selected?.event_id === event.event_id ? 'bg-muted/40' : ''" @click="selected = event">
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

    <div v-if="selected" class="space-y-3 rounded-lg border border-border/60 p-3 text-sm">
      <div class="flex flex-wrap items-center gap-2">
        <span class="font-mono text-xs text-muted-foreground">{{ selected.event_id }}</span>
        <Badge variant="outline">{{ selected.source }}</Badge>
        <Badge variant="outline" :class="decisionClass(selected.decision)">{{ selected.decision }}</Badge>
        <Badge variant="outline">{{ selected.outcome }}</Badge>
        <Badge v-if="selected.risk_level" variant="outline">{{ selected.risk_level }}</Badge>
        <Badge v-if="!selected.actor_verified" variant="outline">{{ t("settings.audit.unverifiedActor") }}</Badge>
      </div>
      <div class="grid gap-1 text-xs text-muted-foreground sm:grid-cols-2">
        <span>{{ t("settings.audit.columnTime") }}: {{ formatTime(selected.occurred_at) }}</span>
        <span>{{ t("settings.audit.columnActor") }}: {{ selected.actor.id }} ({{ selected.actor.kind }})</span>
        <span>{{ t("settings.audit.clientIp") }}: {{ selected.client_ip || "—" }}</span>
        <span>{{ t("settings.audit.requestId") }}: {{ selected.request_id || "—" }}</span>
        <span v-if="selected.execution_id">{{ t("settings.audit.execution") }}: {{ selected.execution_id }}</span>
        <span v-if="selected.statement_index != null">{{ t("settings.audit.statementIndex") }}: {{ selected.statement_index }}</span>
        <span v-if="selected.affected_rows != null">{{ t("settings.audit.affectedRows") }}: {{ selected.affected_rows }}</span>
        <span v-if="selected.redaction_mode">{{ t("settings.audit.retention") }}: {{ selected.redaction_mode }}</span>
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
  </div>
</template>

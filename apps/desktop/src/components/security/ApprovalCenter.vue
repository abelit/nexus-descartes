<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Check, Copy, KeyRound, LoaderCircle, Pencil, Play, Plus, RefreshCw, Trash2, X } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import ApprovalTemplateDialog from "@/components/security/ApprovalTemplateDialog.vue";
import { useToast } from "@/composables/useToast";
import { copyToClipboard } from "@/lib/common/clipboard";
import { formatError } from "@/lib/backend/errorUtils";
import * as approvalsApi from "@/lib/backend/approvals";
import type { ApprovalStep, ApprovalRequest, ApprovalTemplate } from "@/lib/backend/approvals";

const props = withDefaults(
  defineProps<{ focusRequestId?: string; initialScope?: "mine" | "pending"; canManageTemplates?: boolean }>(),
  { canManageTemplates: true },
);

const { t } = useI18n();
const { toast } = useToast();

type ApprovalScope = "mine" | "pending" | "history";
const scope = ref<ApprovalScope>(props.focusRequestId ? "pending" : (props.initialScope ?? "mine"));
const HISTORY_PAGE_SIZE = 50;
const historyStatus = ref("");
const historyQuery = ref("");
const historyRange = ref<"all" | "24" | "168" | "720">("all");
const historyHasMore = ref(false);
const historyLoading = ref(false);
const focusedRequestId = ref(props.focusRequestId ?? "");
const requests = ref<ApprovalRequest[]>([]);
const templates = ref<ApprovalTemplate[]>([]);
const comments = ref<Record<string, string>>({});
const loading = ref(false);
const error = ref("");
const busyId = ref("");
const issuedToken = ref("");
const showTemplates = ref(false);
const templateDialogOpen = ref(false);
const editingTemplate = ref<ApprovalTemplate | null>(null);

const empty = computed(() => !loading.value && requests.value.length === 0);

watch(
  () => props.focusRequestId,
  (requestId) => {
    if (!requestId) return;
    focusedRequestId.value = requestId;
    if (!requests.value.some((request) => request.id === requestId)) {
      scope.value = "pending";
      void refresh();
    }
  },
);

function historyParams(offset: number) {
  const hours = historyRange.value === "all" ? undefined : Number(historyRange.value);
  return {
    history: true,
    status: historyStatus.value || undefined,
    q: historyQuery.value.trim() || undefined,
    from_ms: hours ? Date.now() - hours * 60 * 60 * 1000 : undefined,
    limit: HISTORY_PAGE_SIZE,
    offset,
  };
}

async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    requests.value = await approvalsApi.listApprovals(
      scope.value === "history"
        ? historyParams(0)
        : scope.value === "mine"
          ? { mine: true }
          : { status: "pending", assigned: true },
    );
    historyHasMore.value = scope.value === "history" && requests.value.length === HISTORY_PAGE_SIZE;
    if (focusedRequestId.value && !requests.value.some((request) => request.id === focusedRequestId.value)) {
      try {
        const detail = await approvalsApi.getApproval(focusedRequestId.value);
        if (detail) requests.value = [detail];
      } catch {
        // The request may not be visible from this role; keep the normal list.
      }
    }
    templates.value = await approvalsApi.listApprovalTemplates();
    await nextTick();
    if (focusedRequestId.value) {
      document.querySelector<HTMLElement>(`[data-approval-request-id="${focusedRequestId.value}"]`)?.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  } catch (loadError) {
    error.value = formatError(loadError);
    requests.value = [];
    historyHasMore.value = false;
  } finally {
    loading.value = false;
  }
}

async function loadMoreHistory() {
  if (scope.value !== "history" || !historyHasMore.value || historyLoading.value) return;
  historyLoading.value = true;
  try {
    const page = await approvalsApi.listApprovals(historyParams(requests.value.length));
    requests.value = [...requests.value, ...page];
    historyHasMore.value = page.length === HISTORY_PAGE_SIZE;
  } catch (loadError) {
    toast(formatError(loadError));
  } finally {
    historyLoading.value = false;
  }
}

/** Approval views carry resolved display names; fall back to the id if a user was deleted. */
function userLabel(request: ApprovalRequest, userId: string): string {
  return request.user_names?.[userId] || userId;
}

function stepLabel(step: ApprovalStep, request: ApprovalRequest): string {
  if (step.approver_roles.length === 0 && step.approver_users.length === 0) return t("settings.approvals.stepAnyApprover");
  return [...step.approver_roles.map((role) => `@${role}`), ...step.approver_users.map((userId) => userLabel(request, userId))].join(", ");
}

function stepModeLabel(step: ApprovalStep): string {
  return step.mode === "all" ? t("settings.approvals.stepModeAll") : t("settings.approvals.stepModeAny");
}

/** An `all` step stays pending after one vote; don't offer that approver a second vote. */
function hasApprovedCurrentStep(request: ApprovalRequest): boolean {
  return request.steps.find((step) => step.step_no === request.current_step_no)?.my_decision === "approve";
}

function executionModeLabel(request: ApprovalRequest): string {
  if (request.execution_mode === "auto") return t("settings.approvals.executionModeAuto");
  if (request.execution_mode === "last_approver") return t("settings.approvals.executionModeLastApprover");
  return t("settings.approvals.executionModeSubmitter");
}

function templateModeLabel(mode?: string | null): string {
  if (!mode) return t("settings.approvals.templateExecutionModeDefault");
  if (mode === "auto") return t("settings.approvals.executionModeAuto");
  if (mode === "last_approver") return t("settings.approvals.executionModeLastApprover");
  return t("settings.approvals.executionModeSubmitter");
}

async function execute(request: ApprovalRequest) {
  busyId.value = request.id;
  try {
    await approvalsApi.executeApproval(request.id);
    toast(t("settings.approvals.executed"));
    window.dispatchEvent(new Event("dbx:approvals-changed"));
    await refresh();
  } catch (executeError) {
    toast(formatError(executeError));
    await refresh();
  } finally {
    busyId.value = "";
  }
}

async function decide(request: ApprovalRequest, decision: "approve" | "reject") {
  busyId.value = request.id;
  try {
    await approvalsApi.decideApproval(request.id, decision, comments.value[request.id] ?? "");
    comments.value[request.id] = "";
    window.dispatchEvent(new Event("dbx:approvals-changed"));
    await refresh();
  } catch (decisionError) {
    toast(formatError(decisionError));
  } finally {
    busyId.value = "";
  }
}

function openTemplateEditor(template: ApprovalTemplate | null) {
  editingTemplate.value = template;
  templateDialogOpen.value = true;
}

async function onTemplateSaved() {
  try {
    templates.value = await approvalsApi.listApprovalTemplates();
  } catch (loadError) {
    toast(formatError(loadError));
  }
}

async function deleteTemplate(template: ApprovalTemplate) {
  try {
    await approvalsApi.deleteApprovalTemplate(template.id);
    toast(t("settings.approvals.templateDeleted"));
    await onTemplateSaved();
  } catch (deleteError) {
    toast(formatError(deleteError));
  }
}

async function issueToken(request: ApprovalRequest) {
  busyId.value = request.id;
  try {
    const issued = await approvalsApi.issueExecuteToken(request.id);
    issuedToken.value = issued.token;
    await copyToClipboard(issued.token);
    toast(t("settings.approvals.tokenCopied"));
  } catch (tokenError) {
    toast(formatError(tokenError));
  } finally {
    busyId.value = "";
  }
}

async function copyToken() {
  if (!issuedToken.value) return;
  await copyToClipboard(issuedToken.value);
  toast(t("settings.approvals.tokenCopied"));
}

function statusClass(status: string): string {
  if (status === "approved" || status === "executed") return "border-green-500/50 text-green-600 dark:text-green-400";
  if (status === "rejected" || status === "execution_failed") return "border-destructive/50 text-destructive";
  if (status === "pending" || status === "executing") return "border-amber-500/50 text-amber-600 dark:text-amber-400";
  return "border-border text-muted-foreground";
}

function formatTime(ms: number): string {
  return new Date(ms).toLocaleString();
}

onMounted(() => {
  void refresh();
});
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-start justify-between gap-3">
      <div class="space-y-1">
        <h3 class="text-base font-medium">{{ t("settings.approvals.title") }}</h3>
        <p class="text-sm text-muted-foreground">{{ t("settings.approvals.description") }}</p>
      </div>
      <Button variant="outline" size="sm" class="gap-1.5" :disabled="loading" @click="refresh">
        <RefreshCw :class="['h-3.5 w-3.5', loading ? 'animate-spin' : '']" />
        {{ t("settings.audit.refresh") }}
      </Button>
    </div>

    <div class="flex gap-2">
      <Button
        variant="outline"
        size="sm"
        :class="scope === 'mine' ? 'bg-muted' : ''"
        @click="
          scope = 'mine';
          refresh();
        "
      >
        {{ t("settings.approvals.mine") }}
      </Button>
      <Button
        variant="outline"
        size="sm"
        :class="scope === 'pending' ? 'bg-muted' : ''"
        @click="
          scope = 'pending';
          refresh();
        "
      >
        {{ t("settings.approvals.pending") }}
      </Button>
      <Button
        variant="outline"
        size="sm"
        :class="scope === 'history' ? 'bg-muted' : ''"
        @click="
          scope = 'history';
          refresh();
        "
      >
        {{ t("settings.approvals.history") }}
      </Button>
    </div>

    <div v-if="scope === 'history'" class="space-y-2 rounded-lg border border-border/60 p-3">
      <p class="text-xs text-muted-foreground">{{ t("settings.approvals.historyHint") }}</p>
      <div class="flex flex-wrap items-center gap-2">
        <select v-model="historyStatus" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="refresh">
          <option value="">{{ t("settings.approvals.historyStatusAll") }}</option>
          <option v-for="status in ['pending', 'approved', 'executing', 'executed', 'execution_failed', 'rejected']" :key="status" :value="status">{{ status }}</option>
        </select>
        <select v-model="historyRange" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="refresh">
          <option value="all">{{ t("settings.approvals.historyRangeAll") }}</option>
          <option value="24">{{ t("settings.approvals.historyRange24h") }}</option>
          <option value="168">{{ t("settings.approvals.historyRange7d") }}</option>
          <option value="720">{{ t("settings.approvals.historyRange30d") }}</option>
        </select>
        <Input
          v-model="historyQuery"
          class="h-8 min-w-48 flex-1"
          :placeholder="t('settings.approvals.historySearch')"
          @keyup.enter="refresh"
        />
        <Button variant="outline" size="sm" :disabled="loading" @click="refresh">{{ t("settings.audit.refresh") }}</Button>
      </div>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
      {{ error }}
    </p>

    <div v-if="issuedToken" class="space-y-1 rounded-md border border-green-500/40 bg-green-500/10 p-3">
      <div class="text-sm font-medium">{{ t("settings.approvals.tokenIssued") }}</div>
      <div class="flex items-center gap-2">
        <code class="min-w-0 flex-1 truncate rounded bg-background/60 px-2 py-1 font-mono text-xs">{{ issuedToken }}</code>
        <Button variant="outline" size="sm" @click="copyToken"><Copy class="h-3.5 w-3.5" /></Button>
      </div>
      <p class="text-xs text-muted-foreground">{{ t("settings.approvals.tokenHint") }}</p>
    </div>

    <div class="space-y-2 rounded-lg border border-border/60 p-3">
      <button class="flex w-full items-center justify-between text-left" @click="showTemplates = !showTemplates">
        <span class="text-sm font-medium">{{ t("settings.approvals.templatesTitle") }}</span>
        <span class="text-xs text-muted-foreground">{{ templates.length }}</span>
      </button>
      <div v-if="showTemplates" class="space-y-2">
        <p class="text-xs text-muted-foreground">{{ t("settings.approvals.templatesHint") }}</p>
        <div v-for="template in templates" :key="template.id" class="flex items-center justify-between gap-2 rounded-md border border-border/40 p-2 text-sm">
          <div class="min-w-0">
            <div class="truncate">
              <span class="font-medium">{{ template.name }}</span>
              <span class="ml-1 text-xs text-muted-foreground"> · {{ template.scope_type === "global" ? t("settings.identity.scopeGlobal") : template.scope_id }} </span>
              <span class="ml-1 text-xs text-muted-foreground"> · {{ templateModeLabel(template.execution_mode) }} </span>
            </div>
            <div class="truncate text-xs text-muted-foreground">
              {{ template.steps.map((step) => `${step.mode}: ${[...step.roles.map((role) => `@${role}`), ...step.users].join(", ")}`).join(" → ") }}
            </div>
          </div>
          <div class="flex items-center gap-1">
            <Button v-if="props.canManageTemplates" size="sm" variant="outline" class="h-7 gap-1 px-1.5 text-xs" @click="openTemplateEditor(template)">
              <Pencil class="h-3.5 w-3.5" />
              {{ t("settings.approvals.templateEdit") }}
            </Button>
            <Button v-if="props.canManageTemplates" size="sm" variant="outline" class="h-7 gap-1 px-1.5 text-xs text-destructive" @click="deleteTemplate(template)">
              <Trash2 class="h-3.5 w-3.5" />
              {{ t("settings.approvals.templateDelete") }}
            </Button>
          </div>
        </div>
        <div v-if="props.canManageTemplates" class="flex justify-end">
          <Button size="sm" class="gap-1" @click="openTemplateEditor(null)">
            <Plus class="h-3.5 w-3.5" />
            {{ t("settings.approvals.templateCreate") }}
          </Button>
        </div>
      </div>
    </div>

    <ApprovalTemplateDialog v-model:open="templateDialogOpen" :template="editingTemplate" @saved="onTemplateSaved" />

    <div class="space-y-2">
      <div v-for="request in requests" :key="request.id" :data-approval-request-id="request.id" class="space-y-2 rounded-lg border p-3 transition-shadow" :class="focusedRequestId === request.id ? 'border-primary bg-primary/5 ring-2 ring-primary/40' : 'border-border/60'">
        <div class="flex flex-wrap items-center gap-2">
          <Badge variant="outline" :class="statusClass(request.status)">{{ request.status }}</Badge>
          <span class="text-xs text-muted-foreground" :title="request.requester_id">{{ userLabel(request, request.requester_id) }}</span>
          <span class="text-xs text-muted-foreground">· {{ formatTime(request.created_at_ms) }}</span>
          <span class="text-xs text-muted-foreground"> · {{ request.connection_id }}{{ request.database ? ` / ${request.database}` : "" }} </span>
          <Badge v-for="rule in request.rule_ids" :key="rule" variant="outline">{{ rule }}</Badge>
          <Badge variant="outline">{{ executionModeLabel(request) }}</Badge>
          <span v-if="request.executed_by" class="text-xs text-muted-foreground" :title="request.executed_by">
            {{ t("settings.approvals.executedBy", { user: userLabel(request, request.executed_by) }) }}
          </span>
        </div>
        <pre class="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted/40 p-2 font-mono text-xs">{{ request.sql_text }}</pre>
        <p v-if="request.justification" class="text-xs text-muted-foreground">{{ request.justification }}</p>
        <p v-if="request.execution_error" class="text-xs text-destructive">{{ request.execution_error }}</p>
        <div class="flex flex-wrap items-center gap-1.5">
          <span class="text-xs text-muted-foreground">
            {{ t("settings.approvals.stepProgress", { current: request.current_step_no, total: request.step_count }) }}
          </span>
          <Badge v-for="step in request.steps" :key="step.id" variant="outline" :class="step.status === 'rejected' ? 'text-destructive' : step.status === 'approved' ? 'text-green-600 dark:text-green-400' : ''" :title="stepLabel(step, request)">
            {{ step.step_no }} · {{ stepModeLabel(step) }} · {{ step.status }}
          </Badge>
        </div>
        <div class="space-y-1 text-xs text-muted-foreground">
          <div v-for="step in request.steps" :key="`${step.id}-detail`">
            <span class="font-medium">{{ step.step_no }}.</span>
            {{ stepLabel(step, request) }}
            <span v-if="step.required_user_ids.length > (request.status === 'pending' ? 1 : 0)" class="ml-1"> ({{ t("settings.approvals.stepApprovers", { count: step.required_user_ids.length }) }}) </span>
            <span v-if="step.decided_by" class="ml-1" :title="step.decided_by"> · {{ userLabel(request, step.decided_by) }}{{ step.comment ? `: ${step.comment}` : "" }} </span>
          </div>
        </div>
        <div v-if="request.status === 'pending' && (scope === 'pending' || focusedRequestId === request.id)" class="flex flex-wrap items-center gap-1.5">
          <span v-if="hasApprovedCurrentStep(request)" class="text-xs text-muted-foreground">
            {{ t("settings.approvals.waitingForOtherApprovers") }}
          </span>
          <template v-else>
            <Input v-model="comments[request.id]" class="h-7 flex-1 text-xs" :placeholder="t('settings.approvals.commentHint')" />
            <Button variant="outline" size="sm" class="gap-1" :disabled="busyId === request.id" @click="decide(request, 'approve')">
              <Check class="h-3.5 w-3.5" />
              {{ t("settings.approvals.approve") }}
            </Button>
            <Button variant="outline" size="sm" class="gap-1 text-destructive" :disabled="busyId === request.id" @click="decide(request, 'reject')">
              <X class="h-3.5 w-3.5" />
              {{ t("settings.approvals.reject") }}
            </Button>
          </template>
        </div>
        <div v-if="request.status === 'approved' && (scope === 'mine' || focusedRequestId === request.id)" class="flex justify-end gap-1.5">
          <Button v-if="request.execution_mode === 'submitter'" size="sm" class="gap-1" :disabled="busyId === request.id" @click="execute(request)">
            <Play class="h-3.5 w-3.5" />
            {{ t("settings.approvals.executeNow") }}
          </Button>
          <Button variant="outline" size="sm" class="gap-1" :disabled="busyId === request.id" @click="issueToken(request)">
            <KeyRound class="h-3.5 w-3.5" />
            {{ t("settings.approvals.issueToken") }}
          </Button>
        </div>
      </div>
      <div v-if="empty" class="rounded-lg border border-border/60 p-4 text-center text-sm text-muted-foreground">
        {{ t("settings.approvals.empty") }}
      </div>
      <div v-if="scope === 'history' && historyHasMore" class="flex justify-center">
        <Button variant="outline" size="sm" :disabled="historyLoading" @click="loadMoreHistory">
          {{ historyLoading ? t("common.loading") : t("settings.approvals.loadMore") }}
        </Button>
      </div>
      <div v-if="loading" class="flex justify-center py-4">
        <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Check, Copy, KeyRound, LoaderCircle, Plus, RefreshCw, Trash2, X } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { copyToClipboard } from "@/lib/common/clipboard";
import { formatError } from "@/lib/backend/errorUtils";
import * as approvalsApi from "@/lib/backend/approvals";
import type { ApprovalStep, ApprovalRequest, ApprovalTemplate } from "@/lib/backend/approvals";
import { useConnectionStore } from "@/stores/connectionStore";

const { t } = useI18n();
const { toast } = useToast();
const connectionStore = useConnectionStore();

const scope = ref<"mine" | "pending">("mine");
const requests = ref<ApprovalRequest[]>([]);
const templates = ref<ApprovalTemplate[]>([]);
const comments = ref<Record<string, string>>({});
const loading = ref(false);
const error = ref("");
const busyId = ref("");
const issuedToken = ref("");
const showTemplates = ref(false);
const templateName = ref("");
const templateScopeType = ref<"global" | "connection">("global");
const templateScopeConnection = ref("");
const templateSteps = ref('{\n  "steps": [\n    { "mode": "any", "roles": ["dba"], "users": [] }\n  ]\n}');
const templateBusy = ref(false);

const empty = computed(() => !loading.value && requests.value.length === 0);

async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    requests.value = await approvalsApi.listApprovals(scope.value === "mine" ? { mine: true } : { status: "pending", assigned: true });
    templates.value = await approvalsApi.listApprovalTemplates();
  } catch (loadError) {
    error.value = formatError(loadError);
    requests.value = [];
  } finally {
    loading.value = false;
  }
}

function stepLabel(step: ApprovalStep): string {
  if (step.approver_roles.length === 0 && step.approver_users.length === 0) return t("settings.approvals.stepAnyApprover");
  return [...step.approver_roles.map((role) => `@${role}`), ...step.approver_users].join(", ");
}

function stepModeLabel(step: ApprovalStep): string {
  return step.mode === "all" ? t("settings.approvals.stepModeAll") : t("settings.approvals.stepModeAny");
}

async function decide(request: ApprovalRequest, decision: "approve" | "reject") {
  busyId.value = request.id;
  try {
    await approvalsApi.decideApproval(request.id, decision, comments.value[request.id] ?? "");
    comments.value[request.id] = "";
    await refresh();
  } catch (decisionError) {
    toast(formatError(decisionError));
  } finally {
    busyId.value = "";
  }
}

async function createTemplate() {
  if (!templateName.value.trim()) {
    toast(t("settings.approvals.templateNameRequired"));
    return;
  }
  let steps: unknown;
  try {
    steps = JSON.parse(templateSteps.value);
  } catch {
    toast(t("settings.approvals.templateInvalidJson"));
    return;
  }
  templateBusy.value = true;
  try {
    await approvalsApi.createApprovalTemplate({
      name: templateName.value.trim(),
      scope_type: templateScopeType.value,
      scope_id: templateScopeType.value === "connection" ? templateScopeConnection.value : "",
      steps,
    });
    templateName.value = "";
    await refresh();
  } catch (createError) {
    toast(formatError(createError));
  } finally {
    templateBusy.value = false;
  }
}

async function deleteTemplate(template: ApprovalTemplate) {
  try {
    await approvalsApi.deleteApprovalTemplate(template.id);
    await refresh();
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
  if (status === "approved") return "border-green-500/50 text-green-600 dark:text-green-400";
  if (status === "rejected") return "border-destructive/50 text-destructive";
  if (status === "pending") return "border-amber-500/50 text-amber-600 dark:text-amber-400";
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
            </div>
            <div class="truncate text-xs text-muted-foreground">
              {{ template.steps.map((step) => `${step.mode}: ${[...step.roles.map((role) => `@${role}`), ...step.users].join(", ")}`).join(" → ") }}
            </div>
          </div>
          <Button size="sm" variant="outline" class="h-7 gap-1 px-1.5 text-xs" @click="deleteTemplate(template)">
            <Trash2 class="h-3.5 w-3.5" />
            {{ t("settings.approvals.templateDelete") }}
          </Button>
        </div>
        <div class="space-y-2 rounded-md border border-border/40 p-2">
          <div class="flex flex-wrap items-center gap-2">
            <Input v-model="templateName" class="h-8 w-40" :placeholder="t('settings.approvals.templateName')" />
            <select v-model="templateScopeType" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
              <option value="global">{{ t("settings.identity.scopeGlobal") }}</option>
              <option value="connection">{{ t("settings.identity.scopeConnection") }}</option>
            </select>
            <select v-if="templateScopeType === 'connection'" v-model="templateScopeConnection" class="h-8 max-w-48 rounded-md border border-input bg-background px-2 text-sm">
              <option value="">{{ t("settings.identity.scopeSelect") }}</option>
              <option v-for="connection in connectionStore.connections" :key="connection.id" :value="connection.id">
                {{ connection.name }}
              </option>
            </select>
          </div>
          <textarea v-model="templateSteps" spellcheck="false" class="h-32 w-full rounded-md border border-input bg-background p-2 font-mono text-xs" :aria-label="t('settings.approvals.templateSteps')"></textarea>
          <div class="flex justify-end">
            <Button size="sm" class="gap-1" :disabled="templateBusy" @click="createTemplate">
              <Plus class="h-3.5 w-3.5" />
              {{ t("settings.approvals.templateCreate") }}
            </Button>
          </div>
        </div>
      </div>
    </div>

    <div class="space-y-2">
      <div v-for="request in requests" :key="request.id" class="space-y-2 rounded-lg border border-border/60 p-3">
        <div class="flex flex-wrap items-center gap-2">
          <Badge variant="outline" :class="statusClass(request.status)">{{ request.status }}</Badge>
          <span class="text-xs text-muted-foreground">{{ request.requester_id }}</span>
          <span class="text-xs text-muted-foreground">· {{ formatTime(request.created_at_ms) }}</span>
          <span class="text-xs text-muted-foreground"> · {{ request.connection_id }}{{ request.database ? ` / ${request.database}` : "" }} </span>
          <Badge v-for="rule in request.rule_ids" :key="rule" variant="outline">{{ rule }}</Badge>
        </div>
        <pre class="max-h-32 overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted/40 p-2 font-mono text-xs">{{ request.sql_text }}</pre>
        <p v-if="request.justification" class="text-xs text-muted-foreground">{{ request.justification }}</p>
        <div class="flex flex-wrap items-center gap-1.5">
          <span class="text-xs text-muted-foreground">
            {{ t("settings.approvals.stepProgress", { current: request.current_step_no, total: request.step_count }) }}
          </span>
          <Badge v-for="step in request.steps" :key="step.id" variant="outline" :class="step.status === 'rejected' ? 'text-destructive' : step.status === 'approved' ? 'text-green-600 dark:text-green-400' : ''" :title="stepLabel(step)">
            {{ step.step_no }} · {{ stepModeLabel(step) }} · {{ step.status }}
          </Badge>
        </div>
        <div class="space-y-1 text-xs text-muted-foreground">
          <div v-for="step in request.steps" :key="`${step.id}-detail`">
            <span class="font-medium">{{ step.step_no }}.</span>
            {{ stepLabel(step) }}
            <span v-if="step.required_user_ids.length > (request.status === 'pending' ? 1 : 0)" class="ml-1"> ({{ t("settings.approvals.stepApprovers", { count: step.required_user_ids.length }) }}) </span>
            <span v-if="step.decided_by" class="ml-1"> · {{ step.decided_by }}{{ step.comment ? `: ${step.comment}` : "" }} </span>
          </div>
        </div>
        <div v-if="request.status === 'pending' && scope === 'pending'" class="flex flex-wrap items-center gap-1.5">
          <Input v-model="comments[request.id]" class="h-7 flex-1 text-xs" :placeholder="t('settings.approvals.commentHint')" />
          <Button variant="outline" size="sm" class="gap-1" :disabled="busyId === request.id" @click="decide(request, 'approve')">
            <Check class="h-3.5 w-3.5" />
            {{ t("settings.approvals.approve") }}
          </Button>
          <Button variant="outline" size="sm" class="gap-1 text-destructive" :disabled="busyId === request.id" @click="decide(request, 'reject')">
            <X class="h-3.5 w-3.5" />
            {{ t("settings.approvals.reject") }}
          </Button>
        </div>
        <div v-if="request.status === 'approved' && scope === 'mine'" class="flex justify-end gap-1.5">
          <Button variant="outline" size="sm" class="gap-1" :disabled="busyId === request.id" @click="issueToken(request)">
            <KeyRound class="h-3.5 w-3.5" />
            {{ t("settings.approvals.issueToken") }}
          </Button>
        </div>
      </div>
      <div v-if="empty" class="rounded-lg border border-border/60 p-4 text-center text-sm text-muted-foreground">
        {{ t("settings.approvals.empty") }}
      </div>
      <div v-if="loading" class="flex justify-center py-4">
        <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
      </div>
    </div>
  </div>
</template>

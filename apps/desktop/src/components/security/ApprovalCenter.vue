<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Check, Copy, KeyRound, LoaderCircle, RefreshCw, X } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/composables/useToast";
import { copyToClipboard } from "@/lib/common/clipboard";
import { formatError } from "@/lib/backend/errorUtils";
import * as approvalsApi from "@/lib/backend/approvals";
import type { ApprovalRequest } from "@/lib/backend/approvals";

const { t } = useI18n();
const { toast } = useToast();

const scope = ref<"mine" | "pending">("mine");
const requests = ref<ApprovalRequest[]>([]);
const loading = ref(false);
const error = ref("");
const busyId = ref("");
const issuedToken = ref("");

const empty = computed(() => !loading.value && requests.value.length === 0);

async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    requests.value = await approvalsApi.listApprovals(scope.value === "mine" ? { mine: true } : { status: "pending" });
  } catch (loadError) {
    error.value = formatError(loadError);
    requests.value = [];
  } finally {
    loading.value = false;
  }
}

async function decide(request: ApprovalRequest, decision: "approve" | "reject") {
  busyId.value = request.id;
  try {
    await approvalsApi.decideApproval(request.id, decision);
    await refresh();
  } catch (decisionError) {
    toast(formatError(decisionError));
  } finally {
    busyId.value = "";
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
        <div class="flex justify-end gap-1.5">
          <Button v-if="request.status === 'pending' && scope === 'pending'" variant="outline" size="sm" class="gap-1" :disabled="busyId === request.id" @click="decide(request, 'approve')">
            <Check class="h-3.5 w-3.5" />
            {{ t("settings.approvals.approve") }}
          </Button>
          <Button v-if="request.status === 'pending' && scope === 'pending'" variant="outline" size="sm" class="gap-1 text-destructive" :disabled="busyId === request.id" @click="decide(request, 'reject')">
            <X class="h-3.5 w-3.5" />
            {{ t("settings.approvals.reject") }}
          </Button>
          <Button v-if="request.status === 'approved' && scope === 'mine'" variant="outline" size="sm" class="gap-1" :disabled="busyId === request.id" @click="issueToken(request)">
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

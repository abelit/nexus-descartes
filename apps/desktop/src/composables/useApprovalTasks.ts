import { computed, onBeforeUnmount, ref, watch, type Ref } from "vue";
import { useI18n } from "vue-i18n";
import { useToast } from "@/composables/useToast";
import * as approvalsApi from "@/lib/backend/approvals";
import type { ApprovalRequest } from "@/lib/backend/approvals";
import { isTauriRuntime } from "@/lib/backend/tauriRuntime";

export type ApprovalTaskStatus =
  | "pending"
  | "approved"
  | "executing"
  | "executed"
  | "execution_failed"
  | "rejected"
  | "expired"
  | "cancelled";

export interface ApprovalTask {
  id: string;
  status: ApprovalTaskStatus;
  sql: string;
  connectionId: string;
  database: string;
  stepCount: number;
  currentStepNo: number;
  executionMode: string;
  executionError?: string | null;
  createdAtMs: number;
  executedAtMs?: number | null;
}

const ACTIVE_STATUSES = new Set(["pending", "approved", "executing"]);
const TERMINAL_STATUSES = new Set(["executed", "execution_failed", "rejected", "expired", "cancelled"]);
const TERMINAL_RETENTION_MS = 60 * 60 * 1000;
const IDLE_POLL_MS = 15_000;
const EXECUTING_POLL_MS = 3_000;
const MAX_TASKS = 20;

function toTask(request: ApprovalRequest): ApprovalTask {
  return {
    id: request.id,
    status: request.status as ApprovalTaskStatus,
    sql: request.sql_text,
    connectionId: request.connection_id,
    database: request.database,
    stepCount: request.step_count,
    currentStepNo: request.current_step_no,
    executionMode: request.execution_mode,
    executionError: request.execution_error,
    createdAtMs: request.created_at_ms,
    executedAtMs: request.executed_at_ms,
  };
}

/**
 * Polls the requester's own approvals and exposes them as task-center entries.
 * Approvals are server-owned, so a page refresh rehydrates from the next poll.
 * Only the web build has the approval API; desktop stays idle.
 */
export function useApprovalTasks(enabled: Ref<boolean>) {
  const { t } = useI18n();
  const { toast } = useToast();
  const tasks = ref<ApprovalTask[]>([]);
  const previousStatus = new Map<string, string>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let disposed = false;
  let loading = false;

  const activeCount = computed(() => tasks.value.filter((task) => ACTIVE_STATUSES.has(task.status)).length);
  const failedCount = computed(() => tasks.value.filter((task) => task.status === "execution_failed").length);

  function open(id: string): void {
    window.dispatchEvent(new CustomEvent("dbx:open-approval", { detail: { approvalId: id } }));
  }

  function notifyTerminal(task: ApprovalTask): void {
    const message = task.status === "executed" ? t("taskCenter.executed") : t("taskCenter.executionFailed");
    toast(message, 6000, { label: t("taskCenter.view"), onClick: () => open(task.id) });
  }

  async function refresh(): Promise<void> {
    if (loading || disposed || !enabled.value || isTauriRuntime()) return;
    loading = true;
    try {
      const requests = await approvalsApi.listApprovals({ mine: true });
      const now = Date.now();
      const mapped = requests
        .filter((request) => {
          if (ACTIVE_STATUSES.has(request.status)) return true;
          if (!TERMINAL_STATUSES.has(request.status)) return false;
          const finishedAt = request.executed_at_ms ?? request.created_at_ms;
          return finishedAt > now - TERMINAL_RETENTION_MS;
        })
        .slice(0, MAX_TASKS)
        .map(toTask);
      for (const task of mapped) {
        const previous = previousStatus.get(task.id);
        if (previous && ACTIVE_STATUSES.has(previous) && TERMINAL_STATUSES.has(task.status)) {
          notifyTerminal(task);
        }
        previousStatus.set(task.id, task.status);
      }
      tasks.value = mapped;
    } catch {
      // A permission change or a transient network error should not break the
      // task center; the next tick retries while the feature is enabled.
    } finally {
      loading = false;
    }
  }

  function schedulePoll(): void {
    if (disposed || !enabled.value || isTauriRuntime()) return;
    const delay = tasks.value.some((task) => task.status === "executing") ? EXECUTING_POLL_MS : IDLE_POLL_MS;
    timer = setTimeout(async () => {
      timer = undefined;
      await refresh();
      schedulePoll();
    }, delay);
  }

  watch(
    enabled,
    (on) => {
      if (on) {
        void refresh().finally(schedulePoll);
      } else {
        tasks.value = [];
        previousStatus.clear();
        if (timer) {
          clearTimeout(timer);
          timer = undefined;
        }
      }
    },
    { immediate: true },
  );

  onBeforeUnmount(() => {
    disposed = true;
    if (timer) clearTimeout(timer);
    timer = undefined;
  });

  return { tasks, activeCount, failedCount, open, refresh };
}

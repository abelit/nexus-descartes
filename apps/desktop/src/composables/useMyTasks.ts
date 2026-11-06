import { computed, onBeforeUnmount, ref, watch, type Ref } from "vue";
import { useI18n } from "vue-i18n";
import { useToast } from "@/composables/useToast";
import * as myTasksApi from "@/lib/backend/myTasks";
import type { MyTaskAccessRequest, MyTaskApproval } from "@/lib/backend/myTasks";
import { isTauriRuntime } from "@/lib/backend/tauriRuntime";

const ACTIVE_APPROVAL_STATUSES = new Set(["pending", "approved", "executing"]);
const TERMINAL_APPROVAL_STATUSES = new Set(["executed", "execution_failed", "rejected", "expired", "cancelled"]);
const TERMINAL_RETENTION_MS = 60 * 60 * 1000;
const ACCESS_TERMINAL_RETENTION_MS = 24 * 60 * 60 * 1000;
const IDLE_POLL_MS = 15_000;
const EXECUTING_POLL_MS = 3_000;
const MAX_TASKS = 20;

/**
 * Polls the signed-in user's own SQL approvals and access requests. Unlike the
 * approver inbox this requires no governance permission: the server scopes
 * every row to `requester_id = actor.id`. Terminal transitions raise a toast
 * with a deep link.
 */
export function useMyTasks(enabled: Ref<boolean>) {
  const { t } = useI18n();
  const { toast } = useToast();
  const approvals = ref<MyTaskApproval[]>([]);
  const accessRequests = ref<MyTaskAccessRequest[]>([]);
  const pendingApprovals = ref<MyTaskApproval[]>([]);
  const pendingAccessRequests = ref<MyTaskAccessRequest[]>([]);
  const previousApproval = new Map<string, string>();
  const previousAccess = new Map<string, string>();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let disposed = false;
  let loading = false;

  const activeApprovalCount = computed(() => approvals.value.filter((task) => ACTIVE_APPROVAL_STATUSES.has(task.status)).length);
  const pendingAccessCount = computed(() => accessRequests.value.filter((task) => task.status === "pending").length);
  const activeCount = computed(() => activeApprovalCount.value + pendingAccessCount.value);
  const pendingCount = computed(() => pendingApprovals.value.length + pendingAccessRequests.value.length);
  const failedCount = computed(() => approvals.value.filter((task) => task.status === "execution_failed").length);

  function openApproval(id: string): void {
    window.dispatchEvent(new CustomEvent("dbx:open-approval", { detail: { approvalId: id } }));
  }

  function openAccessRequest(id: string): void {
    window.dispatchEvent(new CustomEvent("dbx:open-access-request", { detail: { requestId: id } }));
  }

  function openAccessApprovals(): void {
    window.dispatchEvent(new CustomEvent("dbx:open-access-approvals"));
  }

  function notifyApproval(task: MyTaskApproval): void {
    const message = task.status === "executed" ? t("taskCenter.executed") : t("taskCenter.executionFailed");
    toast(message, 6000, { label: t("taskCenter.view"), onClick: () => openApproval(task.id) });
  }

  function notifyAccessRequest(task: MyTaskAccessRequest): void {
    const message = task.status === "approved" ? t("taskCenter.accessApproved", { role: task.role_name }) : t("taskCenter.accessRejected", { role: task.role_name });
    toast(message, 6000, { label: t("taskCenter.view"), onClick: () => openAccessRequest(task.id) });
  }

  function mapApprovals(now: number, requests: myTasksApi.MyTaskApproval[]): MyTaskApproval[] {
    return requests
      .filter((request) => {
        if (ACTIVE_APPROVAL_STATUSES.has(request.status)) return true;
        if (!TERMINAL_APPROVAL_STATUSES.has(request.status)) return false;
        const finishedAt = request.executed_at_ms ?? request.created_at_ms;
        return finishedAt > now - TERMINAL_RETENTION_MS;
      })
      .slice(0, MAX_TASKS);
  }

  function mapAccessRequests(now: number, requests: MyTaskAccessRequest[]): MyTaskAccessRequest[] {
    return requests
      .filter((request) => {
        if (request.status === "pending") return true;
        const finishedAt = Date.parse(request.updated_at || request.decided_at || request.created_at);
        return !Number.isNaN(finishedAt) && finishedAt > now - ACCESS_TERMINAL_RETENTION_MS;
      })
      .slice(0, MAX_TASKS);
  }

  async function refresh(): Promise<void> {
    if (loading || disposed || !enabled.value || isTauriRuntime()) return;
    if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
    loading = true;
    try {
      const response = await myTasksApi.listMyTasks(MAX_TASKS);
      const now = Date.now();
      const mappedApprovals = mapApprovals(now, response.approvals);
      const mappedAccess = mapAccessRequests(now, response.access_requests);
      for (const task of mappedApprovals) {
        const previous = previousApproval.get(task.id);
        if (previous && ACTIVE_APPROVAL_STATUSES.has(previous) && TERMINAL_APPROVAL_STATUSES.has(task.status)) {
          if (task.status === "executed" || task.status === "execution_failed") notifyApproval(task);
        }
        previousApproval.set(task.id, task.status);
      }
      for (const task of mappedAccess) {
        const previous = previousAccess.get(task.id);
        if (previous === "pending" && (task.status === "approved" || task.status === "rejected")) {
          notifyAccessRequest(task);
        }
        previousAccess.set(task.id, task.status);
      }
      approvals.value = mappedApprovals;
      accessRequests.value = mappedAccess;
      pendingApprovals.value = response.pending_approvals;
      pendingAccessRequests.value = response.pending_access_requests;
    } catch {
      // A transient network error or permission change must not break the task
      // center; the next tick retries while enabled.
    } finally {
      loading = false;
    }
  }

  function schedulePoll(): void {
    if (disposed || !enabled.value || isTauriRuntime()) return;
    const delay = approvals.value.some((task) => task.status === "executing") ? EXECUTING_POLL_MS : IDLE_POLL_MS;
    timer = setTimeout(async () => {
      timer = undefined;
      await refresh();
      schedulePoll();
    }, delay);
  }

  watch(
    enabled,
    (value) => {
      if (value) {
        void refresh();
        schedulePoll();
      }
    },
    { immediate: true },
  );

  onBeforeUnmount(() => {
    disposed = true;
    if (timer) clearTimeout(timer);
  });

  return {
    approvals,
    accessRequests,
    pendingApprovals,
    pendingAccessRequests,
    activeApprovalCount,
    pendingAccessCount,
    activeCount,
    pendingCount,
    failedCount,
    openApproval,
    openAccessRequest,
    openAccessApprovals,
    refresh,
  };
}

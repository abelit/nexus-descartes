<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Scale, ScrollText, ShieldCheck, Users } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { useConnectionStore } from "@/stores/connectionStore";
import AccessRequestsAdmin from "@/components/security/AccessRequestsAdmin.vue";
import ApprovalCenter from "@/components/security/ApprovalCenter.vue";
import DataPolicies from "@/components/security/DataPolicies.vue";
import AuditLog from "@/components/security/AuditLog.vue";
import PolicyEditor from "@/components/security/PolicyEditor.vue";
import UsersRoles from "@/components/security/UsersRoles.vue";

export type GovernanceTab = "approvals" | "audit" | "users" | "policies";

const props = defineProps<{
  initialTab: GovernanceTab;
  approvalCategory?: "sql" | "access";
  focusApprovalId?: string;
  canApprovals: boolean;
  canAudit: boolean;
  canManageUsers: boolean;
  canReadPolicies: boolean;
  pendingApprovalCount: number;
  actorPermissions?: string[];
  actorRoles?: string[];
  actorId?: string;
}>();

const { t } = useI18n();
const connectionStore = useConnectionStore();
const activeTab = ref<GovernanceTab>(props.initialTab);
const policyView = ref<"rules" | "data">(props.canReadPolicies ? "rules" : "data");
const approvalView = ref<"sql" | "access">(
  props.canApprovals ? (props.approvalCategory ?? "sql") : "access",
);

const canViewAllAudit = computed(() =>
  (props.actorRoles ?? []).some((role) => role === "admin" || role === "security_admin" || role === "auditor"),
);
const canExportAudit = computed(() => props.actorPermissions?.includes("audit:export") ?? false);
const canVerifyAudit = computed(() => props.actorPermissions?.includes("audit:verify") ?? false);
const canManageApprovalTemplates = computed(() => props.actorPermissions?.includes("policy:publish") ?? false);

watch(
  () => props.initialTab,
  (tab) => {
    activeTab.value = tab;
  },
);

watch(
  () => props.approvalCategory,
  (category) => {
    if (category) approvalView.value = category;
  },
);

const tabs = computed(() =>
  [
    props.canApprovals || props.canManageUsers
      ? { value: "approvals" as const, label: t("governance.approvals"), icon: ShieldCheck }
      : null,
    props.canAudit ? { value: "audit" as const, label: t("governance.audit"), icon: ScrollText } : null,
    props.canManageUsers ? { value: "users" as const, label: t("governance.users"), icon: Users } : null,
    props.canReadPolicies || props.canManageUsers
      ? { value: "policies" as const, label: t("governance.policies"), icon: Scale }
      : null,
  ].filter((tab): tab is NonNullable<typeof tab> => tab !== null),
);

watch(
  tabs,
  (available) => {
    if (!available.some((tab) => tab.value === activeTab.value) && available[0]) {
      activeTab.value = available[0].value;
    }
  },
  { immediate: true },
);
</script>

<template>
  <div class="flex h-full min-h-0 flex-col overflow-hidden bg-background">
    <div class="flex flex-wrap items-start justify-between gap-3 border-b border-border/60 px-3 py-4 sm:px-5">
      <div class="min-w-0 space-y-1">
        <div class="flex items-center gap-2">
          <ShieldCheck class="h-5 w-5 text-sky-600 dark:text-sky-400" />
          <h2 class="text-base font-semibold">{{ t("governance.title") }}</h2>
        </div>
        <p class="max-w-3xl text-sm text-muted-foreground">{{ t("governance.description") }}</p>
      </div>
    </div>

    <div class="flex shrink-0 items-center gap-1 overflow-x-auto border-b border-border/60 px-3 sm:px-4">
      <button
        v-for="tab in tabs"
        :key="tab.value"
        type="button"
        class="flex shrink-0 items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm transition-colors"
        :class="activeTab === tab.value ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'"
        :aria-pressed="activeTab === tab.value"
        @click="activeTab = tab.value"
      >
        <component :is="tab.icon" class="h-3.5 w-3.5" />
        {{ tab.label }}
        <Badge v-if="tab.value === 'approvals' && pendingApprovalCount > 0" variant="outline" class="ml-1 h-5 min-w-5 justify-center px-1 text-[10px]">
          {{ pendingApprovalCount > 99 ? "99+" : pendingApprovalCount }}
        </Badge>
      </button>
    </div>

    <div v-if="activeTab === 'approvals'" class="flex shrink-0 items-center gap-1 border-b border-border/60 px-3 sm:px-5">
      <button
        v-if="canApprovals"
        type="button"
        class="border-b-2 px-3 py-2 text-sm transition-colors"
        :class="approvalView === 'sql' ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'"
        @click="approvalView = 'sql'"
      >
        {{ t("governance.sqlApprovals") }}
      </button>
      <button
        v-if="canManageUsers"
        type="button"
        class="border-b-2 px-3 py-2 text-sm transition-colors"
        :class="approvalView === 'access' ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'"
        @click="approvalView = 'access'"
      >
        {{ t("governance.accessApprovals") }}
      </button>
    </div>

    <div v-if="activeTab === 'policies'" class="flex shrink-0 items-center gap-1 border-b border-border/60 px-3 sm:px-5">
      <button
        v-if="canReadPolicies"
        type="button"
        class="border-b-2 px-3 py-2 text-sm transition-colors"
        :class="policyView === 'rules' ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'"
        @click="policyView = 'rules'"
      >
        {{ t("governance.rulePolicies") }}
      </button>
      <button
        v-if="canManageUsers"
        type="button"
        class="border-b-2 px-3 py-2 text-sm transition-colors"
        :class="policyView === 'data' ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'"
        @click="policyView = 'data'"
      >
        {{ t("governance.dataPolicyPolicies") }}
      </button>
    </div>

    <div class="min-h-0 flex-1 overflow-auto px-3 py-4 sm:px-5">
      <ApprovalCenter
        v-if="activeTab === 'approvals' && approvalView === 'sql' && canApprovals"
        :focus-request-id="focusApprovalId"
        :initial-scope="pendingApprovalCount > 0 ? 'pending' : 'mine'"
        :can-manage-templates="canManageApprovalTemplates"
      />
      <AccessRequestsAdmin
        v-else-if="activeTab === 'approvals' && approvalView === 'access' && canManageUsers"
        :actor-id="actorId"
      />
      <AuditLog
        v-else-if="activeTab === 'audit' && canAudit"
        session-authorized
        :can-view-all="canViewAllAudit"
        :can-export="canExportAudit"
        :can-verify="canVerifyAudit"
      />
      <UsersRoles
        v-else-if="activeTab === 'users' && canManageUsers"
        :actor-permissions="actorPermissions"
        :actor-roles="actorRoles"
        :actor-id="actorId"
      />
      <PolicyEditor v-else-if="activeTab === 'policies' && policyView === 'rules' && canReadPolicies" />
      <DataPolicies
        v-else-if="activeTab === 'policies' && policyView === 'data' && canManageUsers"
        :connections="connectionStore.connections"
      />
      <p v-else class="text-sm text-muted-foreground">{{ t("governance.noPermission") }}</p>
    </div>
  </div>
</template>

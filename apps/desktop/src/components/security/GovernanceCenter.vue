<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { ScrollText, ShieldCheck, UserCog } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import ApprovalCenter from "@/components/security/ApprovalCenter.vue";
import AuditLog from "@/components/security/AuditLog.vue";

const props = defineProps<{
  initialTab: "approvals" | "audit";
  canApprovals: boolean;
  canAudit: boolean;
  canOpenSecuritySettings: boolean;
  pendingApprovalCount: number;
}>();

const emit = defineEmits<{
  "open-security-settings": [];
}>();

const { t } = useI18n();
const activeTab = ref<"approvals" | "audit">(props.initialTab);

watch(
  () => props.initialTab,
  (tab) => {
    activeTab.value = tab;
  },
);

const tabs = computed(() =>
  [props.canApprovals ? { value: "approvals" as const, label: t("governance.approvals"), icon: ShieldCheck } : null, props.canAudit ? { value: "audit" as const, label: t("governance.audit"), icon: ScrollText } : null].filter((tab): tab is NonNullable<typeof tab> => tab !== null),
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

function openSettings() {
  emit("open-security-settings");
}
</script>

<template>
  <div class="flex h-full min-h-0 flex-col overflow-hidden bg-background">
    <div class="flex flex-wrap items-start justify-between gap-3 border-b border-border/60 px-5 py-4">
      <div class="min-w-0 space-y-1">
        <div class="flex items-center gap-2">
          <ShieldCheck class="h-5 w-5 text-sky-600 dark:text-sky-400" />
          <h2 class="text-base font-semibold">{{ t("governance.title") }}</h2>
        </div>
        <p class="max-w-3xl text-sm text-muted-foreground">{{ t("governance.description") }}</p>
      </div>
      <Button v-if="canOpenSecuritySettings" variant="outline" size="sm" class="gap-1.5" @click="openSettings">
        <UserCog class="h-3.5 w-3.5" />
        {{ t("governance.openSecuritySettings") }}
      </Button>
    </div>

    <div class="flex shrink-0 items-center gap-1 border-b border-border/60 px-4">
      <button
        v-for="tab in tabs"
        :key="tab.value"
        type="button"
        class="flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm transition-colors"
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

    <div class="min-h-0 flex-1 overflow-auto px-5 py-4">
      <ApprovalCenter v-if="activeTab === 'approvals' && canApprovals" />
      <AuditLog v-else-if="activeTab === 'audit' && canAudit" session-authorized />
      <p v-else class="text-sm text-muted-foreground">{{ t("governance.noPermission") }}</p>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as approvalsApi from "@/lib/backend/approvals";
import { useConnectionStore } from "@/stores/connectionStore";

export interface ApprovalRequiredRequest {
  tabId: string;
  connectionId: string;
  database: string;
  schema?: string;
  sql: string;
  detail: string;
}

const props = defineProps<{
  open: boolean;
  request: ApprovalRequiredRequest | null;
}>();

const emit = defineEmits<{
  "update:open": [open: boolean];
  created: [id: string];
}>();

const { t } = useI18n();
const { toast } = useToast();
const connectionStore = useConnectionStore();

const justification = ref("");
const busy = ref(false);

const connectionName = computed(() => {
  const id = props.request?.connectionId;
  if (!id) return "";
  return connectionStore.getConfig(id)?.name ?? id;
});

const targetLabel = computed(() => {
  const request = props.request;
  if (!request) return "";
  return [request.database, request.schema].filter(Boolean).join(" / ");
});

watch(
  () => props.open,
  (open) => {
    if (open) {
      justification.value = "";
    }
  },
);

async function submit() {
  const request = props.request;
  if (!request || busy.value) return;
  busy.value = true;
  try {
    const created = await approvalsApi.createApproval({
      connection_id: request.connectionId,
      database: request.database,
      ...(request.schema ? { schema_name: request.schema } : {}),
      sql: request.sql,
      justification: justification.value.trim(),
    });
    toast(t("settings.approvals.requestCreated"));
    emit("created", created.id);
    emit("update:open", false);
  } catch (error) {
    toast(formatError(error), 6000);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <Dialog :open="open" @update:open="(value) => emit('update:open', value)">
    <DialogContent class="sm:max-w-[680px]">
      <DialogHeader>
        <DialogTitle>{{ t("settings.approvals.approvalRequiredTitle") }}</DialogTitle>
      </DialogHeader>
      <div class="space-y-3">
        <p class="text-sm text-muted-foreground">{{ t("settings.approvals.approvalRequiredHint") }}</p>
        <div class="grid gap-1 text-xs text-muted-foreground">
          <div>
            <span class="font-medium text-foreground">{{ t("settings.approvals.target") }}:</span> {{ connectionName }} · {{ targetLabel }}
          </div>
          <div class="break-all">
            <span class="font-medium text-foreground">{{ t("settings.approvals.rule") }}:</span> {{ request?.detail ?? "" }}
          </div>
        </div>
        <pre class="max-h-56 overflow-auto rounded-md border border-border/60 bg-muted/40 p-3 text-xs whitespace-pre-wrap">{{ request?.sql ?? "" }}</pre>
        <label class="block space-y-1 text-sm">
          <span class="text-muted-foreground">{{ t("settings.approvals.justification") }}</span>
          <textarea v-model="justification" rows="3" class="w-full rounded-md border border-input bg-background px-3 py-2 text-sm" :placeholder="t('settings.approvals.justificationHint')" />
        </label>
        <p class="rounded-md border border-border/60 bg-muted/30 p-2 text-xs text-muted-foreground">
          {{ t("settings.approvals.executionModeFromTemplate") }}
        </p>
      </div>
      <DialogFooter>
        <Button variant="outline" :disabled="busy" @click="emit('update:open', false)">
          {{ t("dangerDialog.cancel") }}
        </Button>
        <Button :disabled="busy" @click="submit">
          {{ t("settings.approvals.submitRequest") }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>

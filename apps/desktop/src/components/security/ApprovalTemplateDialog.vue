<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { ArrowDown, ArrowUp, LoaderCircle, Plus, Trash2 } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as approvalsApi from "@/lib/backend/approvals";
import type { ApprovalTemplate } from "@/lib/backend/approvals";
import { listRoles, listUsers, type LocalRole, type LocalUser } from "@/lib/backend/users";
import { useConnectionStore } from "@/stores/connectionStore";

interface StepDraft {
  mode: "any" | "all";
  roles: string[];
  users: string[];
}

const props = defineProps<{ open: boolean; template: ApprovalTemplate | null }>();
const emit = defineEmits<{ "update:open": [open: boolean]; saved: [] }>();

const { t } = useI18n();
const { toast } = useToast();
const connectionStore = useConnectionStore();

const name = ref("");
const scopeType = ref<"global" | "connection">("global");
const scopeConnection = ref("");
const enabled = ref(true);
const slaSecs = ref("");
const executionMode = ref<"" | "submitter" | "last_approver" | "auto">("");
const mode = ref<"form" | "json">("form");
const steps = ref<StepDraft[]>([]);
const jsonText = ref("");
const jsonError = ref("");
const error = ref("");
const saving = ref(false);

const roles = ref<LocalRole[]>([]);
const users = ref<LocalUser[]>([]);
const directoriesAvailable = ref(true);
const userSearch = ref("");

const builtinRoles = ["admin", "security_admin", "auditor", "dba", "operator", "viewer"];
const availableRoles = computed(() => (roles.value.length ? roles.value.map((role) => role.code) : builtinRoles));
const filteredUsers = computed(() => {
  const query = userSearch.value.trim().toLowerCase();
  return users.value
    .filter((user) => user.status === "active")
    .filter((user) => !query || user.email.toLowerCase().includes(query) || user.display_name.toLowerCase().includes(query))
    .slice(0, 40);
});

const title = computed(() => (props.template ? t("settings.approvals.templateEdit") : t("settings.approvals.templateCreate")));

function normalizeSteps(value: unknown): StepDraft[] {
  const raw = Array.isArray(value) ? value : (value as { steps?: unknown } | null)?.steps;
  if (!Array.isArray(raw)) throw new Error(t("settings.approvals.templateInvalidJson"));
  return raw.map((entry) => {
    const step = (entry ?? {}) as Record<string, unknown>;
    return {
      mode: step.mode === "all" ? "all" : "any",
      roles: Array.isArray(step.roles) ? step.roles.map(String) : [],
      users: Array.isArray(step.users) ? step.users.map(String) : [],
    };
  });
}

function syncJson() {
  jsonText.value = JSON.stringify({ steps: steps.value }, null, 2);
}

function reset() {
  const template = props.template;
  name.value = template?.name ?? "";
  scopeType.value = template?.scope_type === "connection" ? "connection" : "global";
  scopeConnection.value = template?.scope_type === "connection" ? template.scope_id : "";
  enabled.value = template?.enabled ?? true;
  slaSecs.value = template?.sla_secs != null ? String(template.sla_secs) : "";
  executionMode.value = template?.execution_mode ?? "";
  steps.value = template?.steps?.length
    ? template.steps.map((step) => ({
        mode: step.mode === "all" ? "all" : "any",
        roles: [...step.roles],
        users: [...step.users],
      }))
    : [{ mode: "any", roles: ["dba"], users: [] }];
  mode.value = "form";
  jsonError.value = "";
  error.value = "";
  userSearch.value = "";
  syncJson();
}

async function loadDirectories() {
  directoriesAvailable.value = true;
  try {
    const [roleList, userList] = await Promise.all([listRoles(), listUsers()]);
    roles.value = roleList;
    users.value = userList;
  } catch {
    // Template managers may lack user-management access; fall back to the
    // built-in role list and raw user ids.
    directoriesAvailable.value = false;
    roles.value = [];
    users.value = [];
  }
}

watch(
  () => props.open,
  (open) => {
    if (!open) return;
    reset();
    void loadDirectories();
  },
  { immediate: true },
);
watch(
  () => props.template,
  () => {
    if (props.open) reset();
  },
);

function switchMode(next: "form" | "json") {
  if (next === mode.value) return;
  if (next === "json") {
    syncJson();
    jsonError.value = "";
    mode.value = "json";
    return;
  }
  try {
    steps.value = normalizeSteps(JSON.parse(jsonText.value));
    jsonError.value = "";
    mode.value = "form";
  } catch (parseError) {
    jsonError.value = formatError(parseError);
  }
}

function addStep() {
  steps.value.push({ mode: "any", roles: [], users: [] });
}

function removeStep(index: number) {
  steps.value.splice(index, 1);
}

function moveStep(index: number, delta: number) {
  const target = index + delta;
  if (target < 0 || target >= steps.value.length) return;
  const [step] = steps.value.splice(index, 1);
  steps.value.splice(target, 0, step);
}

function toggleRole(step: StepDraft, role: string) {
  const index = step.roles.indexOf(role);
  if (index >= 0) step.roles.splice(index, 1);
  else step.roles.push(role);
}

function toggleUser(step: StepDraft, userId: string) {
  const index = step.users.indexOf(userId);
  if (index >= 0) step.users.splice(index, 1);
  else step.users.push(userId);
}

function setUsers(step: StepDraft, value: string) {
  step.users = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function userName(userId: string): string {
  return users.value.find((user) => user.id === userId)?.display_name || userId;
}

function collectSteps(): StepDraft[] {
  const list = mode.value === "json" ? normalizeSteps(JSON.parse(jsonText.value)) : steps.value;
  if (!list.length) throw new Error(t("settings.approvals.templateStepsRequired"));
  for (const [index, step] of list.entries()) {
    if (!step.roles.length && !step.users.length) {
      throw new Error(t("settings.approvals.templateStepApproverRequired", { step: index + 1 }));
    }
  }
  return list;
}

async function save() {
  error.value = "";
  jsonError.value = "";
  let list: StepDraft[];
  try {
    list = collectSteps();
  } catch (validationError) {
    if (mode.value === "json") jsonError.value = formatError(validationError);
    else error.value = formatError(validationError);
    return;
  }
  if (!name.value.trim()) {
    error.value = t("settings.approvals.templateNameRequired");
    return;
  }
  if (scopeType.value === "connection" && !scopeConnection.value) {
    error.value = t("settings.approvals.templateConnectionRequired");
    return;
  }
  const sla = Number(slaSecs.value);
  const payload = {
    name: name.value.trim(),
    scope_type: scopeType.value,
    scope_id: scopeType.value === "connection" ? scopeConnection.value : "",
    steps: list,
    enabled: enabled.value,
    sla_secs: Number.isFinite(sla) && sla > 0 ? Math.trunc(sla) : null,
    execution_mode: executionMode.value || null,
  };
  saving.value = true;
  try {
    if (props.template) await approvalsApi.updateApprovalTemplate(props.template.id, payload);
    else await approvalsApi.createApprovalTemplate(payload);
    toast(props.template ? t("settings.approvals.templateUpdated") : t("settings.approvals.templateCreated"));
    emit("saved");
    emit("update:open", false);
  } catch (saveError) {
    error.value = formatError(saveError);
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <Dialog :open="open" @update:open="emit('update:open', $event)">
    <DialogContent class="max-h-[88vh] overflow-y-auto sm:max-w-3xl">
      <DialogHeader>
        <DialogTitle>{{ title }}</DialogTitle>
      </DialogHeader>

      <div class="space-y-3">
        <div class="grid gap-2 sm:grid-cols-2">
          <label class="space-y-1 text-xs">
            <span class="text-muted-foreground">{{ t("settings.approvals.templateName") }}</span>
            <Input v-model="name" class="h-8" :placeholder="t('settings.approvals.templateName')" />
          </label>
          <label class="space-y-1 text-xs">
            <span class="text-muted-foreground">{{ t("settings.approvals.templateScope") }}</span>
            <div class="flex gap-2">
              <select v-model="scopeType" class="h-8 flex-1 rounded-md border border-input bg-background px-2 text-sm">
                <option value="global">{{ t("settings.identity.scopeGlobal") }}</option>
                <option value="connection">{{ t("settings.identity.scopeConnection") }}</option>
              </select>
              <select v-if="scopeType === 'connection'" v-model="scopeConnection" class="h-8 flex-1 rounded-md border border-input bg-background px-2 text-sm">
                <option value="">{{ t("settings.identity.scopeSelect") }}</option>
                <option v-for="connection in connectionStore.connections" :key="connection.id" :value="connection.id">
                  {{ connection.name }}
                </option>
              </select>
            </div>
          </label>
          <label class="flex items-center gap-2 text-xs">
            <input v-model="enabled" type="checkbox" class="h-4 w-4" />
            {{ t("settings.approvals.templateEnabled") }}
          </label>
          <label class="space-y-1 text-xs">
            <span class="text-muted-foreground">{{ t("settings.approvals.templateSla") }}</span>
            <Input v-model="slaSecs" type="number" min="0" class="h-8" :placeholder="t('settings.approvals.templateSlaPlaceholder')" />
          </label>
          <label class="space-y-1 text-xs sm:col-span-2">
            <span class="text-muted-foreground">{{ t("settings.approvals.templateExecutionMode") }}</span>
            <select v-model="executionMode" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
              <option value="">{{ t("settings.approvals.templateExecutionModeDefault") }}</option>
              <option value="last_approver">{{ t("settings.approvals.executionModeLastApprover") }}</option>
              <option value="submitter">{{ t("settings.approvals.executionModeSubmitter") }}</option>
              <option value="auto">{{ t("settings.approvals.executionModeAuto") }}</option>
            </select>
            <span class="text-[11px] text-muted-foreground">{{ t("settings.approvals.templateExecutionModeHint") }}</span>
          </label>
        </div>

        <div class="flex items-center gap-1">
          <Button size="sm" :variant="mode === 'form' ? 'default' : 'outline'" class="h-7 text-xs" @click="switchMode('form')">
            {{ t("settings.approvals.templateFormMode") }}
          </Button>
          <Button size="sm" :variant="mode === 'json' ? 'default' : 'outline'" class="h-7 text-xs" @click="switchMode('json')">
            {{ t("settings.approvals.templateJsonMode") }}
          </Button>
        </div>

        <template v-if="mode === 'form'">
          <div class="space-y-2">
            <div v-for="(step, index) in steps" :key="index" class="space-y-2 rounded-md border border-border/60 p-2">
              <div class="flex flex-wrap items-center gap-2">
                <span class="text-xs font-medium">{{ t("settings.approvals.templateStep", { step: index + 1 }) }}</span>
                <select v-model="step.mode" class="h-7 rounded-md border border-input bg-background px-2 text-xs">
                  <option value="any">{{ t("settings.approvals.stepModeAny") }}</option>
                  <option value="all">{{ t("settings.approvals.stepModeAll") }}</option>
                </select>
                <span class="flex-1"></span>
                <Button size="sm" variant="outline" class="h-7 w-7 p-0" :disabled="index === 0" :title="t('settings.approvals.templateMoveUp')" @click="moveStep(index, -1)">
                  <ArrowUp class="h-3.5 w-3.5" />
                </Button>
                <Button size="sm" variant="outline" class="h-7 w-7 p-0" :disabled="index === steps.length - 1" :title="t('settings.approvals.templateMoveDown')" @click="moveStep(index, 1)">
                  <ArrowDown class="h-3.5 w-3.5" />
                </Button>
                <Button size="sm" variant="outline" class="h-7 w-7 p-0 text-destructive" :title="t('settings.approvals.templateDelete')" @click="removeStep(index)">
                  <Trash2 class="h-3.5 w-3.5" />
                </Button>
              </div>

              <div class="space-y-1">
                <span class="text-[11px] text-muted-foreground">{{ t("settings.approvals.templateRoles") }}</span>
                <div class="flex flex-wrap gap-1">
                  <button
                    v-for="role in availableRoles"
                    :key="role"
                    type="button"
                    class="rounded-full border px-2 py-0.5 text-[11px]"
                    :class="step.roles.includes(role) ? 'border-primary bg-primary/10 text-primary' : 'border-border text-muted-foreground'"
                    @click="toggleRole(step, role)"
                  >
                    @{{ role }}
                  </button>
                </div>
              </div>

              <div class="space-y-1">
                <span class="text-[11px] text-muted-foreground">{{ t("settings.approvals.templateUsers") }}</span>
                <div v-if="step.users.length" class="flex flex-wrap gap-1">
                  <button
                    v-for="userId in step.users"
                    :key="userId"
                    type="button"
                    class="rounded-full border border-border px-2 py-0.5 text-[11px]"
                    :title="userId"
                    @click="toggleUser(step, userId)"
                  >
                    {{ userName(userId) }} ×
                  </button>
                </div>
                <template v-if="directoriesAvailable">
                  <Input v-model="userSearch" class="h-7 text-xs" :placeholder="t('settings.approvals.templateUserSearch')" />
                  <div class="max-h-28 overflow-y-auto rounded-md border border-border/40">
                    <button
                      v-for="user in filteredUsers"
                      :key="user.id"
                      type="button"
                      class="flex w-full items-center justify-between gap-2 px-2 py-1 text-left text-[11px] hover:bg-muted"
                      @click="toggleUser(step, user.id)"
                    >
                      <span class="truncate">{{ user.display_name }} <span class="text-muted-foreground">{{ user.email }}</span></span>
                      <span v-if="step.users.includes(user.id)" class="text-primary">✓</span>
                    </button>
                  </div>
                </template>
                <Input
                  v-else
                  class="h-7 text-xs"
                  :placeholder="t('settings.approvals.templateUserIds')"
                  :model-value="step.users.join(', ')"
                  @update:model-value="setUsers(step, String($event))"
                />
              </div>
            </div>
          </div>
          <Button size="sm" variant="outline" class="h-7 gap-1 text-xs" @click="addStep">
            <Plus class="h-3.5 w-3.5" />
            {{ t("settings.approvals.templateAddStep") }}
          </Button>
        </template>

        <div v-else class="space-y-1">
          <textarea v-model="jsonText" spellcheck="false" class="h-64 w-full rounded-md border border-input bg-background p-2 font-mono text-xs" />
          <p v-if="jsonError" class="text-xs text-destructive">{{ jsonError }}</p>
        </div>

        <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">{{ error }}</p>
      </div>

      <DialogFooter>
        <Button variant="outline" @click="emit('update:open', false)">{{ t("common.cancel") }}</Button>
        <Button class="gap-1" :disabled="saving" @click="save">
          <LoaderCircle v-if="saving" class="h-3.5 w-3.5 animate-spin" />
          {{ t("common.save") }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>

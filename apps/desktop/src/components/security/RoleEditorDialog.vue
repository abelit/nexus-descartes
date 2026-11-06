<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { LoaderCircle, RotateCcw, Search } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type { LocalRole } from "@/lib/backend/users";

const props = defineProps<{
  open: boolean;
  role?: LocalRole | null;
  actorPermissions?: string[];
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "saved"): void;
}>();

const { t } = useI18n();
const { toast } = useToast();

const PERMISSION_GROUPS: { key: string; labelKey: string; permissions: string[] }[] = [
  {
    key: "data",
    labelKey: "settings.identity.permissionGroupData",
    permissions: ["connection:read", "connection:write", "query:read", "query:write", "query:ddl", "export:data", "import:data", "unmask:data", "row_filter:bypass"],
  },
  {
    key: "approval",
    labelKey: "settings.identity.permissionGroupApproval",
    permissions: ["approval:read", "approval:act", "approval:bypass", "policy:read", "policy:write", "policy:publish"],
  },
  {
    key: "audit",
    labelKey: "settings.identity.permissionGroupAudit",
    permissions: ["audit:read", "audit:export", "audit:verify"],
  },
  {
    key: "admin",
    labelKey: "settings.identity.permissionGroupAdmin",
    permissions: ["admin:users", "admin:settings", "admin:plugins"],
  },
];

const form = reactive({ code: "", name: "", description: "" });
const selectedPermissions = ref<string[]>([]);
const search = ref("");
const busy = ref(false);
const resetArmed = ref(false);
const error = ref("");

const isEdit = computed(() => !!props.role);
const isBuiltin = computed(() => props.role?.builtin === true);
const isAdminRole = computed(() => props.role?.code === "admin");
const canReset = computed(() => isBuiltin.value && !isAdminRole.value);
const codeValid = computed(() => /^[a-z0-9_.-]{1,64}$/.test(form.code.trim()));
const exceedsCeiling = computed(() => {
  const granted = props.actorPermissions ?? [];
  if (granted.length === 0) return false;
  return selectedPermissions.value.some((permission) => !granted.includes(permission));
});
const canSave = computed(() => {
  if (!form.name.trim() || selectedPermissions.value.length === 0 || exceedsCeiling.value) return false;
  if (!isEdit.value && !codeValid.value) return false;
  return true;
});
const visibleGroups = computed(() => {
  const query = search.value.trim().toLowerCase();
  return PERMISSION_GROUPS.map((group) => ({
    ...group,
    permissions: group.permissions.filter((permission) => !query || permission.toLowerCase().includes(query)),
  })).filter((group) => group.permissions.length > 0);
});

function initialize() {
  error.value = "";
  resetArmed.value = false;
  search.value = "";
  form.code = props.role?.code ?? "";
  form.name = props.role?.name ?? "";
  form.description = props.role?.description ?? "";
  selectedPermissions.value = [...(props.role?.permissions ?? [])];
}

function togglePermission(permission: string) {
  const current = selectedPermissions.value;
  selectedPermissions.value = current.includes(permission) ? current.filter((value) => value !== permission) : [...current, permission];
}

async function save() {
  if (!canSave.value || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    if (props.role) {
      await usersApi.updateRole(props.role.code, {
        name: form.name.trim(),
        description: form.description.trim(),
        permissions: selectedPermissions.value,
      });
      toast(t("settings.identity.roleUpdatedToast"));
    } else {
      await usersApi.createRole({
        code: form.code.trim(),
        name: form.name.trim(),
        description: form.description.trim(),
        permissions: selectedPermissions.value,
      });
      toast(t("settings.identity.roleCreatedToast"));
    }
    emit("saved");
    emit("update:open", false);
  } catch (saveError) {
    error.value = formatError(saveError);
  } finally {
    busy.value = false;
  }
}

async function resetToDefault() {
  if (!props.role || !canReset.value || busy.value) return;
  if (!resetArmed.value) {
    resetArmed.value = true;
    return;
  }
  busy.value = true;
  error.value = "";
  try {
    await usersApi.deleteRole(props.role.code);
    toast(t("settings.identity.roleResetToast"));
    emit("saved");
    emit("update:open", false);
  } catch (resetError) {
    error.value = formatError(resetError);
  } finally {
    busy.value = false;
  }
}

watch(
  () => props.open,
  (open) => {
    if (open) initialize();
  },
  { immediate: true },
);
</script>

<template>
  <Dialog :open="props.open" @update:open="(value) => emit('update:open', value)">
    <DialogContent class="max-h-[calc(var(--dbx-viewport-height)-2rem)] w-full max-w-2xl overflow-y-auto">
      <DialogTitle class="text-base font-medium">
        {{ isEdit ? t("settings.identity.editRoleTitle", { name: props.role?.name ?? "" }) : t("settings.identity.newRoleTitle") }}
      </DialogTitle>
      <p class="text-xs text-muted-foreground">
        {{ isBuiltin ? t("settings.identity.builtinRoleHint") : t("settings.identity.customRoleHint") }}
      </p>

      <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">{{ error }}</p>

      <div class="grid gap-3 sm:grid-cols-2">
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.identity.roleCode") }}</span>
          <Input v-model="form.code" class="h-8" :disabled="isEdit" :placeholder="t('settings.identity.roleCode')" />
          <span v-if="!isEdit && form.code && !codeValid" class="text-destructive">
            {{ t("settings.identity.roleCodeInvalid") }}
          </span>
        </label>
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.identity.columnRole") }}</span>
          <Input v-model="form.name" class="h-8" :placeholder="t('settings.identity.columnRole')" />
        </label>
        <label class="space-y-1 text-xs sm:col-span-2">
          <span class="text-muted-foreground">{{ t("settings.identity.roleDescription") }}</span>
          <Input v-model="form.description" class="h-8" :placeholder="t('settings.identity.roleDescription')" />
        </label>
      </div>

      <div class="flex items-center justify-between gap-2">
        <div class="relative flex-1">
          <Search class="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input v-model="search" class="h-8 pl-7" :placeholder="t('settings.identity.searchPermissions')" />
        </div>
        <Badge variant="outline">{{ t("settings.identity.permissionsSelected", { count: selectedPermissions.length }) }}</Badge>
      </div>

      <div class="space-y-3">
        <section v-for="group in visibleGroups" :key="group.key" class="space-y-1.5 rounded-lg border border-border/60 p-2.5">
          <div class="text-xs font-medium">{{ t(group.labelKey) }}</div>
          <div class="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
            <label v-for="permission in group.permissions" :key="permission" class="flex items-center gap-1.5 text-xs">
              <input type="checkbox" :aria-label="permission" :checked="selectedPermissions.includes(permission)" :disabled="isAdminRole" @change="togglePermission(permission)" />
              <span class="truncate font-mono">{{ permission }}</span>
            </label>
          </div>
        </section>
      </div>

      <p v-if="exceedsCeiling" class="text-xs text-destructive">{{ t("settings.identity.roleAboveCeiling") }}</p>
      <p v-if="isAdminRole" class="text-xs text-muted-foreground">{{ t("settings.identity.builtinAdminRoleLocked") }}</p>

      <div class="flex flex-wrap items-center justify-between gap-2">
        <Button v-if="canReset" size="sm" variant="outline" class="text-destructive" :disabled="busy" @click="resetToDefault">
          <RotateCcw class="mr-1 h-3.5 w-3.5" />
          {{ resetArmed ? t("settings.identity.roleResetConfirm") : t("settings.identity.roleResetToDefault") }}
        </Button>
        <span v-else />
        <div class="flex gap-2">
          <Button size="sm" variant="outline" @click="emit('update:open', false)">{{ t("settings.identity.cancel") }}</Button>
          <Button size="sm" :disabled="busy || !canSave || isAdminRole" @click="save">
            <LoaderCircle v-if="busy" class="mr-1 h-3.5 w-3.5 animate-spin" />
            {{ isEdit ? t("settings.identity.saveRole") : t("settings.identity.create") }}
          </Button>
        </div>
      </div>
    </DialogContent>
  </Dialog>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { LoaderCircle } from "@lucide/vue";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type { LocalRole, LocalUser } from "@/lib/backend/users";

const props = defineProps<{
  open: boolean;
  user?: LocalUser | null;
  roles: LocalRole[];
  actorPermissions?: string[];
  actorRoles?: string[];
  actorId?: string;
}>();

const emit = defineEmits<{
  (event: "update:open", value: boolean): void;
  (event: "saved"): void;
}>();

const { t } = useI18n();
const { toast } = useToast();

const form = reactive({
  email: "",
  displayName: "",
  password: "",
  roleCode: "",
});
const busy = ref(false);
const error = ref("");

const isEdit = computed(() => !!props.user);
const actorGlobalPermissions = computed(() => {
  const codes = new Set(props.actorRoles ?? []);
  if (codes.size === 0) return props.actorPermissions ?? [];
  const permissions = new Set<string>();
  for (const role of props.roles) {
    if (codes.has(role.code)) for (const permission of role.permissions) permissions.add(permission);
  }
  return [...permissions];
});
const assignableRoles = computed(() => {
  if (actorGlobalPermissions.value.length === 0) return props.roles;
  return props.roles.filter((role) => role.permissions.every((permission) => actorGlobalPermissions.value.includes(permission)));
});
const roleOptions = computed(() => {
  const options = [...assignableRoles.value];
  const current = props.user?.roles[0];
  if (current && !options.some((role) => role.code === current)) {
    const role = props.roles.find((candidate) => candidate.code === current);
    if (role) options.unshift(role);
  }
  return options;
});
const selectedRole = computed(() => props.roles.find((role) => role.code === form.roleCode));
const roleExceedsCeiling = computed(() => !!selectedRole.value && actorGlobalPermissions.value.length > 0 && selectedRole.value.permissions.some((permission) => !actorGlobalPermissions.value.includes(permission)));
const roleLocked = computed(() => props.user?.is_builtin === true);

const canSave = computed(() => {
  if (!form.displayName.trim()) return false;
  if (!isEdit.value && (!form.email.trim() || form.password.length < 8)) return false;
  if (form.roleCode && roleExceedsCeiling.value) return false;
  return true;
});

function initialize() {
  error.value = "";
  form.email = props.user?.email ?? "";
  form.displayName = props.user?.display_name ?? "";
  form.password = "";
  form.roleCode = props.user ? (props.user.roles[0] ?? "none") : (assignableRoles.value.find((role) => role.code === "viewer")?.code ?? assignableRoles.value[0]?.code ?? "");
}

async function save() {
  if (!canSave.value || busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    if (!props.user) {
      const created = await usersApi.createUser({
        email: form.email.trim(),
        display_name: form.displayName.trim(),
        password: form.password,
        role: form.roleCode && form.roleCode !== "none" ? form.roleCode : "viewer",
      });
      if (form.roleCode === "none") {
        await usersApi.updateUser(created.id, { clear_global_role: true });
      }
      toast(t("settings.identity.userCreated"));
    } else {
      const user = props.user;
      if (form.displayName.trim() !== user.display_name) {
        await usersApi.updateUser(user.id, { display_name: form.displayName.trim() });
      }
      const previousRole = user.roles[0] ?? "none";
      if (!roleLocked.value && form.roleCode !== previousRole) {
        if (form.roleCode === "none") {
          await usersApi.updateUser(user.id, { clear_global_role: true });
        } else {
          await usersApi.updateUser(user.id, { role: form.roleCode });
        }
      }
      toast(t("settings.identity.userUpdated"));
    }
    emit("saved");
    emit("update:open", false);
  } catch (saveError) {
    error.value = formatError(saveError);
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
    <DialogContent class="max-h-[calc(var(--dbx-viewport-height)-2rem)] w-full max-w-xl overflow-y-auto">
      <DialogTitle class="text-base font-medium">
        {{ isEdit ? t("settings.identity.editUserTitle") : t("settings.identity.newUserTitle") }}
      </DialogTitle>
      <p class="text-xs text-muted-foreground">
        {{ isEdit ? t("settings.identity.editUserHint") : t("settings.identity.createThenGrantHint") }}
      </p>

      <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-2 text-xs text-destructive">{{ error }}</p>

      <div class="grid gap-3 sm:grid-cols-2">
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.identity.email") }}</span>
          <Input v-model="form.email" class="h-8" type="email" :disabled="isEdit" :placeholder="t('settings.identity.email')" />
        </label>
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.identity.displayName") }}</span>
          <Input v-model="form.displayName" class="h-8" :placeholder="t('settings.identity.displayName')" />
        </label>
        <label v-if="!isEdit" class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.identity.password") }}</span>
          <Input v-model="form.password" class="h-8" type="password" :placeholder="t('settings.identity.password')" />
        </label>
        <label class="space-y-1 text-xs">
          <span class="text-muted-foreground">{{ t("settings.identity.globalRole") }}</span>
          <select v-model="form.roleCode" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm" :disabled="roleLocked">
            <option value="none">{{ t("settings.identity.noGlobalRole") }}</option>
            <option v-for="role in roleOptions" :key="role.code" :value="role.code">{{ role.name }}</option>
          </select>
        </label>
      </div>

      <p v-if="!isEdit && form.password.length > 0 && form.password.length < 8" class="text-xs text-destructive">
        {{ t("settings.identity.passwordHint") }}
      </p>
      <p v-if="roleExceedsCeiling" class="text-xs text-destructive">{{ t("settings.identity.roleAboveCeiling") }}</p>
      <p v-if="roleLocked" class="text-xs text-muted-foreground">{{ t("settings.identity.builtinAdminRoleLocked") }}</p>

      <div class="flex justify-end gap-2">
        <Button size="sm" variant="outline" @click="emit('update:open', false)">{{ t("settings.identity.cancel") }}</Button>
        <Button size="sm" :disabled="busy || !canSave" @click="save">
          <LoaderCircle v-if="busy" class="mr-1 h-3.5 w-3.5 animate-spin" />
          {{ isEdit ? t("settings.identity.saveRole") : t("settings.identity.create") }}
        </Button>
      </div>
    </DialogContent>
  </Dialog>
</template>

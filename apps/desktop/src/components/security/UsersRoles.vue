<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { Check, KeyRound, LoaderCircle, Pencil, RefreshCw, ShieldOff, Trash2, UserPlus, X } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type { LocalRole, LocalUser, UserSession } from "@/lib/backend/users";

const { t } = useI18n();
const { toast } = useToast();

const PERMISSIONS = [
  "audit:read",
  "audit:export",
  "audit:verify",
  "policy:read",
  "policy:write",
  "policy:publish",
  "approval:read",
  "approval:act",
  "approval:bypass",
  "connection:read",
  "connection:write",
  "query:read",
  "query:write",
  "query:ddl",
  "export:data",
  "import:data",
  "admin:users",
  "admin:settings",
  "admin:plugins",
];

const users = ref<LocalUser[]>([]);
const roles = ref<LocalRole[]>([]);
const loading = ref(false);
const error = ref("");
const busyUserId = ref("");

const draftEmail = ref("");
const draftName = ref("");
const draftPassword = ref("");
const draftRole = ref("viewer");

const sessionsUserId = ref("");
const sessions = ref<UserSession[]>([]);

const passwordUserId = ref("");
const passwordDraft = ref("");

const nameUserId = ref("");
const nameDraft = ref("");

const roleDraft = ref({ code: "", name: "", description: "", permissions: [] as string[] });
const editingRoleCode = ref("");

const canLoad = computed(() => error.value === "" || users.value.length > 0);
const customRoles = computed(() => roles.value.filter((role) => !role.builtin));

async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    users.value = await usersApi.listUsers();
    roles.value = await usersApi.listRoles();
  } catch (loadError) {
    error.value = formatError(loadError);
    users.value = [];
  } finally {
    loading.value = false;
  }
}

async function createUser() {
  if (!draftEmail.value.trim() || draftPassword.value.length < 8) {
    toast(t("settings.identity.invalidDraft"));
    return;
  }
  loading.value = true;
  try {
    await usersApi.createUser({
      email: draftEmail.value.trim(),
      display_name: draftName.value.trim(),
      password: draftPassword.value,
      role: draftRole.value,
    });
    draftEmail.value = "";
    draftName.value = "";
    draftPassword.value = "";
    draftRole.value = "viewer";
    await refresh();
  } catch (createError) {
    toast(formatError(createError));
  } finally {
    loading.value = false;
  }
}

function onRoleChange(user: LocalUser, event: Event) {
  const value = (event.target as HTMLSelectElement).value;
  void changeRole(user, value);
}

async function savePasswordForSelected() {
  const user = users.value.find((item) => item.id === passwordUserId.value);
  if (user) await resetPassword(user);
}

async function changeRole(user: LocalUser, role: string) {
  if (role === user.roles[0]) return;
  busyUserId.value = user.id;
  try {
    await usersApi.updateUser(user.id, { role });
    await refresh();
  } catch (updateError) {
    toast(formatError(updateError));
  } finally {
    busyUserId.value = "";
  }
}

async function setStatus(user: LocalUser, status: "active" | "disabled") {
  busyUserId.value = user.id;
  try {
    await usersApi.updateUser(user.id, { status });
    await refresh();
  } catch (updateError) {
    toast(formatError(updateError));
  } finally {
    busyUserId.value = "";
  }
}

async function revokeSessions(user: LocalUser) {
  busyUserId.value = user.id;
  try {
    await usersApi.revokeUserSessions(user.id);
    if (sessionsUserId.value === user.id) sessions.value = [];
    toast(t("settings.identity.sessionsRevoked"));
  } catch (revokeError) {
    toast(formatError(revokeError));
  } finally {
    busyUserId.value = "";
  }
}

async function revokeAllSessionsForSelected() {
  const user = users.value.find((item) => item.id === sessionsUserId.value);
  if (user) await revokeSessions(user);
  sessions.value = [];
}

async function toggleSessions(user: LocalUser) {
  if (sessionsUserId.value === user.id) {
    sessionsUserId.value = "";
    sessions.value = [];
    return;
  }
  sessionsUserId.value = user.id;
  try {
    sessions.value = await usersApi.listUserSessions(user.id);
  } catch (sessionError) {
    toast(formatError(sessionError));
    sessions.value = [];
  }
}

async function revokeSession(session: UserSession) {
  try {
    await usersApi.revokeUserSession(sessionsUserId.value, session.id);
    sessions.value = sessions.value.filter((item) => item.id !== session.id);
  } catch (sessionError) {
    toast(formatError(sessionError));
  }
}

async function resetPassword(user: LocalUser) {
  if (passwordUserId.value !== user.id) {
    passwordUserId.value = user.id;
    passwordDraft.value = "";
    return;
  }
  if (passwordDraft.value.length < 8) {
    toast(t("settings.identity.invalidDraft"));
    return;
  }
  busyUserId.value = user.id;
  try {
    await usersApi.resetUserPassword(user.id, passwordDraft.value);
    passwordUserId.value = "";
    passwordDraft.value = "";
    toast(t("settings.identity.passwordReset"));
  } catch (resetError) {
    toast(formatError(resetError));
  } finally {
    busyUserId.value = "";
  }
}

async function saveDisplayName(user: LocalUser) {
  if (nameUserId.value !== user.id) {
    nameUserId.value = user.id;
    nameDraft.value = user.display_name;
    return;
  }
  if (!nameDraft.value.trim()) return;
  busyUserId.value = user.id;
  try {
    await usersApi.updateUser(user.id, { display_name: nameDraft.value.trim() });
    nameUserId.value = "";
    await refresh();
  } catch (updateError) {
    toast(formatError(updateError));
  } finally {
    busyUserId.value = "";
  }
}

function startRoleEdit(role?: LocalRole) {
  editingRoleCode.value = role?.code ?? "";
  roleDraft.value = role ? { code: role.code, name: role.name, description: role.description, permissions: [...role.permissions] } : { code: "", name: "", description: "", permissions: [] };
}

function togglePermission(permission: string) {
  const current = roleDraft.value.permissions;
  roleDraft.value.permissions = current.includes(permission) ? current.filter((value) => value !== permission) : [...current, permission];
}

async function saveRole() {
  if (!roleDraft.value.name.trim() || (!editingRoleCode.value && !roleDraft.value.code.trim())) {
    toast(t("settings.identity.invalidRole"));
    return;
  }
  try {
    if (editingRoleCode.value) {
      await usersApi.updateRole(editingRoleCode.value, {
        name: roleDraft.value.name.trim(),
        description: roleDraft.value.description,
        permissions: roleDraft.value.permissions,
      });
    } else {
      await usersApi.createRole({
        code: roleDraft.value.code.trim(),
        name: roleDraft.value.name.trim(),
        description: roleDraft.value.description,
        permissions: roleDraft.value.permissions,
      });
    }
    startRoleEdit();
    await refresh();
  } catch (roleError) {
    toast(formatError(roleError));
  }
}

async function deleteRole(role: LocalRole) {
  try {
    await usersApi.deleteRole(role.code);
    if (editingRoleCode.value === role.code) startRoleEdit();
    await refresh();
  } catch (roleError) {
    toast(formatError(roleError));
  }
}

function roleLabel(code: string): string {
  return roles.value.find((role) => role.code === code)?.name ?? code;
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
        <h3 class="text-base font-medium">{{ t("settings.identity.title") }}</h3>
        <p class="text-sm text-muted-foreground">{{ t("settings.identity.description") }}</p>
      </div>
      <Button variant="outline" size="sm" class="gap-1.5" :disabled="loading" @click="refresh">
        <RefreshCw :class="['h-3.5 w-3.5', loading ? 'animate-spin' : '']" />
        {{ t("settings.audit.refresh") }}
      </Button>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
      {{ error }}
    </p>

    <div v-if="canLoad" class="space-y-2 rounded-lg border border-border/60 p-3">
      <div class="flex items-center gap-2 text-sm font-medium">
        <UserPlus class="h-4 w-4" />
        {{ t("settings.identity.createTitle") }}
      </div>
      <div class="flex flex-wrap gap-2">
        <Input v-model="draftEmail" class="h-8 w-52" :placeholder="t('settings.identity.email')" />
        <Input v-model="draftName" class="h-8 w-40" :placeholder="t('settings.identity.displayName')" />
        <Input v-model="draftPassword" type="password" class="h-8 w-44" :placeholder="t('settings.identity.password')" />
        <select v-model="draftRole" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
          <option v-for="role in roles" :key="role.code" :value="role.code">{{ role.name }}</option>
        </select>
        <Button size="sm" :disabled="loading" @click="createUser">{{ t("settings.identity.create") }}</Button>
      </div>
      <p class="text-xs text-muted-foreground">{{ t("settings.identity.passwordHint") }}</p>
    </div>

    <div v-if="canLoad" class="overflow-hidden rounded-lg border border-border/60">
      <table class="w-full table-fixed text-sm">
        <thead class="bg-muted/40 text-left text-xs text-muted-foreground">
          <tr>
            <th class="px-3 py-2 font-medium">{{ t("settings.identity.columnUser") }}</th>
            <th class="w-44 px-3 py-2 font-medium">{{ t("settings.identity.columnRole") }}</th>
            <th class="w-28 px-3 py-2 font-medium">{{ t("settings.identity.columnStatus") }}</th>
            <th class="w-40 px-3 py-2 font-medium">{{ t("settings.identity.columnLastLogin") }}</th>
            <th class="w-56 px-3 py-2 text-right font-medium">{{ t("settings.identity.columnActions") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in users" :key="user.id" class="border-t border-border/40">
            <td class="px-3 py-2">
              <div v-if="nameUserId === user.id" class="flex items-center gap-1">
                <Input v-model="nameDraft" class="h-7 text-xs" />
                <Button size="sm" variant="outline" class="h-7 px-1.5" @click="saveDisplayName(user)">
                  <Check class="h-3.5 w-3.5" />
                </Button>
              </div>
              <template v-else>
                <div class="truncate font-medium">{{ user.display_name }}</div>
                <div class="truncate text-xs text-muted-foreground">{{ user.email }}</div>
              </template>
            </td>
            <td class="px-3 py-2">
              <select v-if="!user.is_builtin" class="h-7 w-full rounded-md border border-input bg-background px-1.5 text-xs" :value="user.roles[0] ?? ''" :disabled="busyUserId === user.id" @change="onRoleChange(user, $event)">
                <option v-for="role in roles" :key="role.code" :value="role.code">{{ role.name }}</option>
              </select>
              <Badge v-else variant="outline">{{ roleLabel(user.roles[0] ?? "admin") }}</Badge>
            </td>
            <td class="px-3 py-2">
              <Badge variant="outline" :class="user.status === 'active' ? 'text-green-600 dark:text-green-400' : 'text-muted-foreground'">
                {{ user.status }}
              </Badge>
            </td>
            <td class="truncate px-3 py-2 text-xs text-muted-foreground">
              {{ user.last_login_at ? new Date(user.last_login_at).toLocaleString() : "—" }}
            </td>
            <td class="px-3 py-2">
              <div class="flex justify-end gap-1">
                <Button size="sm" variant="outline" class="h-7 px-1.5" :title="t('settings.identity.editName')" @click="saveDisplayName(user)">
                  <Pencil class="h-3.5 w-3.5" />
                </Button>
                <Button size="sm" variant="outline" class="h-7 px-1.5" :title="t('settings.identity.resetPassword')" @click="resetPassword(user)">
                  <KeyRound class="h-3.5 w-3.5" />
                </Button>
                <Button size="sm" variant="outline" class="h-7 px-1.5" :title="t('settings.identity.sessions')" @click="toggleSessions(user)">
                  <ShieldOff class="h-3.5 w-3.5" />
                </Button>
                <Button v-if="!user.is_builtin" size="sm" variant="outline" class="h-7 px-1.5 text-xs" :disabled="busyUserId === user.id" @click="setStatus(user, user.status === 'active' ? 'disabled' : 'active')">
                  {{ user.status === "active" ? t("settings.identity.disable") : t("settings.identity.enable") }}
                </Button>
              </div>
            </td>
          </tr>
          <tr v-if="!loading && users.length === 0">
            <td colspan="5" class="px-3 py-6 text-center text-muted-foreground">{{ t("settings.identity.empty") }}</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="passwordUserId" class="flex items-center gap-2 rounded-md border border-border/60 p-2">
      <span class="text-xs text-muted-foreground">{{ t("settings.identity.newPassword") }}</span>
      <Input v-model="passwordDraft" type="password" class="h-8 w-56" @keyup.enter="savePasswordForSelected" />
      <Button size="sm" @click="savePasswordForSelected">
        {{ t("settings.identity.savePassword") }}
      </Button>
      <Button size="sm" variant="outline" @click="passwordUserId = ''">
        <X class="h-3.5 w-3.5" />
      </Button>
    </div>

    <div v-if="sessionsUserId" class="space-y-2 rounded-md border border-border/60 p-3">
      <div class="flex items-center justify-between">
        <div class="text-sm font-medium">{{ t("settings.identity.sessions") }}</div>
        <Button size="sm" variant="outline" class="h-6 text-xs" @click="revokeAllSessionsForSelected">
          {{ t("settings.identity.revokeAll") }}
        </Button>
      </div>
      <p v-if="sessions.length === 0" class="text-xs text-muted-foreground">{{ t("settings.identity.noSessions") }}</p>
      <div v-for="session in sessions" :key="session.id" class="flex items-center justify-between gap-2 text-xs">
        <span class="truncate text-muted-foreground"> {{ session.client_ip || "—" }} · {{ session.user_agent || "—" }} · {{ formatTime(session.last_seen_at_ms) }} </span>
        <Button size="sm" variant="outline" class="h-6 px-1.5" @click="revokeSession(session)">
          <Trash2 class="h-3 w-3" />
        </Button>
      </div>
    </div>

    <div class="space-y-2 rounded-lg border border-border/60 p-3">
      <div class="flex items-center justify-between">
        <div class="text-sm font-medium">{{ t("settings.identity.customRoles") }}</div>
        <Button size="sm" variant="outline" @click="startRoleEdit()">{{ t("settings.identity.createRole") }}</Button>
      </div>
      <div v-for="role in customRoles" :key="role.code" class="flex items-center justify-between gap-2 rounded-md border border-border/40 p-2 text-sm">
        <div class="min-w-0">
          <div class="truncate font-medium">
            {{ role.name }} <span class="text-xs text-muted-foreground">({{ role.code }})</span>
          </div>
          <div class="truncate text-xs text-muted-foreground">{{ role.permissions.join(", ") || "—" }}</div>
        </div>
        <div class="flex gap-1">
          <Button size="sm" variant="outline" class="h-7 px-1.5" @click="startRoleEdit(role)"><Pencil class="h-3.5 w-3.5" /></Button>
          <Button size="sm" variant="outline" class="h-7 px-1.5 text-destructive" @click="deleteRole(role)"><Trash2 class="h-3.5 w-3.5" /></Button>
        </div>
      </div>

      <div v-if="roleDraft.name || roleDraft.code || editingRoleCode" class="space-y-2 rounded-md border border-border/40 p-2">
        <div class="flex flex-wrap gap-2">
          <Input v-model="roleDraft.code" class="h-8 w-40" :disabled="!!editingRoleCode" :placeholder="t('settings.identity.roleCode')" />
          <Input v-model="roleDraft.name" class="h-8 w-44" :placeholder="t('settings.identity.columnRole')" />
          <Input v-model="roleDraft.description" class="h-8 flex-1" :placeholder="t('settings.identity.roleDescription')" />
        </div>
        <div class="grid grid-cols-2 gap-1 text-xs sm:grid-cols-3">
          <span v-for="permission in PERMISSIONS" :key="permission" class="flex items-center gap-1.5">
            <input type="checkbox" :aria-label="permission" :checked="roleDraft.permissions.includes(permission)" @change="togglePermission(permission)" />
            <span class="truncate">{{ permission }}</span>
          </span>
        </div>
        <div class="flex justify-end gap-1.5">
          <Button size="sm" variant="outline" @click="startRoleEdit()">{{ t("settings.identity.cancel") }}</Button>
          <Button size="sm" @click="saveRole">{{ t("settings.identity.saveRole") }}</Button>
        </div>
      </div>
    </div>

    <div v-if="roles.length > 0" class="space-y-1 rounded-lg border border-border/60 p-3">
      <div class="text-sm font-medium">{{ t("settings.identity.rolesTitle") }}</div>
      <div v-for="role in roles.filter((item) => item.builtin)" :key="role.code" class="text-xs text-muted-foreground">
        <span class="font-medium text-foreground">{{ role.name }}</span>
        ({{ role.code }}) — {{ role.description }}
      </div>
    </div>

    <div v-if="loading && !canLoad" class="flex justify-center py-4">
      <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { useI18n } from "vue-i18n";
import { Check, KeyRound, LoaderCircle, Pencil, RefreshCw, ShieldCheck, Trash2, UserPlus, X } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import AccessInventory from "@/components/security/AccessInventory.vue";
import AccessGroups from "@/components/security/AccessGroups.vue";
import UserAccessDialog from "@/components/security/UserAccessDialog.vue";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type { ConnectionGroup, LocalRole, LocalUser } from "@/lib/backend/users";
import { useConnectionStore } from "@/stores/connectionStore";

const props = defineProps<{
  actorPermissions?: string[];
  actorRoles?: string[];
  actorId?: string;
}>();

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
  "unmask:data",
  "row_filter:bypass",
  "admin:users",
  "admin:settings",
  "admin:plugins",
];

const connectionStore = useConnectionStore();
const users = ref<LocalUser[]>([]);
const roles = ref<LocalRole[]>([]);
const groups = ref<ConnectionGroup[]>([]);
const loading = ref(false);
const error = ref("");
const busyUserId = ref("");

const draftEmail = ref("");
const draftName = ref("");
const draftPassword = ref("");
const draftRole = ref("viewer");

const viewMode = ref<"users" | "inventory" | "groups">("users");
const accessGroupsRef = ref<InstanceType<typeof AccessGroups> | null>(null);
const accessOpen = ref(false);
const accessUser = ref<LocalUser | null>(null);
const inventoryVersion = ref(0);

function onAccessChanged() {
  inventoryVersion.value += 1;
  void refresh();
}

async function openGroupFromInventory(groupId: string) {
  viewMode.value = "groups";
  await nextTick();
  await accessGroupsRef.value?.openGroupById(groupId);
}

const groupDraft = ref({ name: "", parentId: "" });
const editingGroupId = ref("");
const groupMembersDraft = ref<string[]>([]);

const passwordUserId = ref("");
const passwordDraft = ref("");

const nameUserId = ref("");
const nameDraft = ref("");

const roleDraft = ref({ code: "", name: "", description: "", permissions: [] as string[] });
const editingRoleCode = ref("");
const roleFormOpen = ref(false);

const canLoad = computed(() => error.value === "" || users.value.length > 0);
const customRoles = computed(() => roles.value.filter((role) => !role.builtin));
const actorPermissions = computed(() => props.actorPermissions ?? []);
// Global role assignment needs globally held permissions. Asset-scoped
// permissions from the actor's own grants must not make a global role look
// assignable when the server would reject it.
const actorGlobalPermissions = computed(() => {
  const codes = new Set(props.actorRoles ?? []);
  if (codes.size === 0) return actorPermissions.value;
  const permissions = new Set<string>();
  for (const role of roles.value) {
    if (codes.has(role.code)) for (const permission of role.permissions) permissions.add(permission);
  }
  return [...permissions];
});
// A role can only be assigned when the actor already holds every permission it
// grants. The server enforces the same rule; filtering here keeps a failed
// request from being the first time the administrator learns about it.
const assignableRoles = computed(() => {
  if (actorGlobalPermissions.value.length === 0) return roles.value;
  return roles.value.filter((role) => role.permissions.every((permission) => actorGlobalPermissions.value.includes(permission)));
});
function roleOptionsFor(user: LocalUser): LocalRole[] {
  const current = user.roles[0];
  const options = [...assignableRoles.value];
  if (current && !options.some((role) => role.code === current)) {
    const role = roles.value.find((candidate) => candidate.code === current);
    if (role) options.unshift(role);
  }
  return options;
}

function openUserAccess(user: LocalUser) {
  accessUser.value = user;
  accessOpen.value = true;
}

function canResetPassword(user: LocalUser): boolean {
  if (user.id === props.actorId) return true;
  if (actorGlobalPermissions.value.length === 0) return true;
  const effective = user.effective_permissions ?? user.permissions ?? [];
  return effective.every((permission) => actorGlobalPermissions.value.includes(permission));
}

function targetHasAdminPermission(user: LocalUser): boolean {
  return (user.permissions ?? []).some((permission) => permission.startsWith("admin:"));
}

function canManageTarget(user: LocalUser): boolean {
  if (!targetHasAdminPermission(user)) return true;
  if (user.id === props.actorId) return true;
  if (actorGlobalPermissions.value.length === 0) return true;
  return (user.permissions ?? []).every((permission) => actorGlobalPermissions.value.includes(permission));
}

function openUserAccessById(userId: string) {
  const user = users.value.find((candidate) => candidate.id === userId);
  if (user) openUserAccess(user);
}

watch(
  () => users.value,
  (list) => {
    if (!accessUser.value) return;
    accessUser.value = list.find((user) => user.id === accessUser.value?.id) ?? null;
  },
);

watch(
  assignableRoles,
  (list) => {
    if (!list.some((role) => role.code === draftRole.value)) draftRole.value = list[0]?.code ?? "viewer";
  },
  { immediate: true },
);

async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    users.value = await usersApi.listUsers();
    roles.value = await usersApi.listRoles();
    groups.value = await usersApi.listConnectionGroups();
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
    draftRole.value = assignableRoles.value[0]?.code ?? "viewer";
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
  roleFormOpen.value = true;
  editingRoleCode.value = role?.code ?? "";
  roleDraft.value = role ? { code: role.code, name: role.name, description: role.description, permissions: [...role.permissions] } : { code: "", name: "", description: "", permissions: [] };
}

function closeRoleEdit() {
  roleFormOpen.value = false;
  editingRoleCode.value = "";
  roleDraft.value = { code: "", name: "", description: "", permissions: [] };
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
    closeRoleEdit();
    await refresh();
  } catch (roleError) {
    toast(formatError(roleError));
  }
}

async function deleteRole(role: LocalRole) {
  try {
    await usersApi.deleteRole(role.code);
    if (editingRoleCode.value === role.code) closeRoleEdit();
    await refresh();
  } catch (roleError) {
    toast(formatError(roleError));
  }
}

function groupName(groupId?: string | null): string {
  if (!groupId) return "—";
  return groups.value.find((group) => group.id === groupId)?.name ?? groupId;
}

async function createGroup() {
  if (!groupDraft.value.name.trim()) return;
  try {
    await usersApi.createConnectionGroup(groupDraft.value.name.trim(), groupDraft.value.parentId || null);
    groupDraft.value = { name: "", parentId: "" };
    await refresh();
  } catch (groupError) {
    toast(formatError(groupError));
  }
}

async function deleteGroup(group: ConnectionGroup) {
  try {
    await usersApi.deleteConnectionGroup(group.id);
    if (editingGroupId.value === group.id) editingGroupId.value = "";
    await refresh();
  } catch (groupError) {
    toast(formatError(groupError));
  }
}

function editGroupMembers(group: ConnectionGroup) {
  editingGroupId.value = editingGroupId.value === group.id ? "" : group.id;
  groupMembersDraft.value = [...group.connection_ids];
}

function toggleGroupMember(connectionId: string) {
  groupMembersDraft.value = groupMembersDraft.value.includes(connectionId) ? groupMembersDraft.value.filter((value) => value !== connectionId) : [...groupMembersDraft.value, connectionId];
}

async function saveGroupMembers(group: ConnectionGroup) {
  try {
    await usersApi.setConnectionGroupMembers(group.id, groupMembersDraft.value);
    await refresh();
  } catch (groupError) {
    toast(formatError(groupError));
  }
}

function roleLabel(code: string): string {
  return roles.value.find((role) => role.code === code)?.name ?? code;
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
      <Button v-if="viewMode === 'users'" variant="outline" size="sm" class="gap-1.5" :disabled="loading" @click="refresh">
        <RefreshCw :class="['h-3.5 w-3.5', loading ? 'animate-spin' : '']" />
        {{ t("settings.audit.refresh") }}
      </Button>
    </div>

    <div class="flex items-center gap-1 border-b border-border/60">
      <button
        type="button"
        class="border-b-2 px-3 py-2 text-sm transition-colors"
        :class="viewMode === 'users' ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'"
        @click="viewMode = 'users'"
      >
        {{ t("settings.identity.usersView") }}
      </button>
      <button
        type="button"
        class="border-b-2 px-3 py-2 text-sm transition-colors"
        :class="viewMode === 'inventory' ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'"
        @click="viewMode = 'inventory'"
      >
        {{ t("settings.identity.inventoryView") }}
      </button>
      <button
        type="button"
        class="border-b-2 px-3 py-2 text-sm transition-colors"
        :class="viewMode === 'groups' ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'"
        @click="viewMode = 'groups'"
      >
        {{ t("settings.identity.groupsTitle") }}
      </button>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
      {{ error }}
    </p>

    <template v-if="viewMode === 'users'">
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
          <option v-for="role in assignableRoles" :key="role.code" :value="role.code">{{ role.name }}</option>
        </select>
        <Button size="sm" :disabled="loading" @click="createUser">{{ t("settings.identity.create") }}</Button>
      </div>
      <p class="text-xs text-muted-foreground">{{ t("settings.identity.passwordHint") }}</p>
      <p class="text-xs text-muted-foreground">{{ t("settings.identity.createThenGrantHint") }}</p>
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
              <template v-if="!user.is_builtin">
                <Badge v-if="user.roles.length === 0" variant="outline">{{ t("settings.identity.assetOnly") }}</Badge>
                <select
                  v-else
                  class="h-7 w-full rounded-md border border-input bg-background px-1.5 text-xs"
                  :value="user.roles[0] ?? ''"
                  :disabled="busyUserId === user.id || !canManageTarget(user)"
                  :title="canManageTarget(user) ? '' : t('settings.identity.roleAboveCeiling')"
                  @change="onRoleChange(user, $event)"
                >
                  <option v-for="role in roleOptionsFor(user)" :key="role.code" :value="role.code">{{ role.name }}</option>
                </select>
                <div v-if="user.asset_roles?.length" class="mt-1 truncate text-[11px] text-muted-foreground">
                  {{ t("settings.identity.assetRoleCount", { count: user.asset_roles.length }) }}
                </div>
              </template>
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
                <Button size="sm" variant="outline" class="h-7 px-1.5" :disabled="!canResetPassword(user)" :title="canResetPassword(user) ? t('settings.identity.resetPassword') : t('settings.identity.resetPasswordCeiling')" @click="resetPassword(user)">
                  <KeyRound class="h-3.5 w-3.5" />
                </Button>
                <Button size="sm" variant="outline" class="h-7 px-1.5 text-xs" :title="t('settings.identity.editUserAccess')" @click="openUserAccess(user)">
                  <ShieldCheck class="mr-1 h-3.5 w-3.5" />
                  {{ t("settings.identity.access") }}
                </Button>
                <Button v-if="!user.is_builtin" size="sm" variant="outline" class="h-7 px-1.5 text-xs" :disabled="busyUserId === user.id || !canManageTarget(user)" @click="setStatus(user, user.status === 'active' ? 'disabled' : 'active')">
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

    <div class="space-y-2 rounded-lg border border-border/60 p-3">
      <div class="text-sm font-medium">{{ t("settings.identity.connectionGroups") }}</div>
      <p class="text-xs text-muted-foreground">{{ t("settings.identity.connectionGroupsHint") }}</p>
      <div class="flex flex-wrap gap-2">
        <Input v-model="groupDraft.name" class="h-8 w-44" :placeholder="t('settings.identity.groupName')" />
        <select v-model="groupDraft.parentId" class="h-8 rounded-md border border-input bg-background px-2 text-sm">
          <option value="">{{ t("settings.identity.groupNoParent") }}</option>
          <option v-for="group in groups" :key="group.id" :value="group.id">{{ group.name }}</option>
        </select>
        <Button size="sm" variant="outline" @click="createGroup">{{ t("settings.identity.createGroup") }}</Button>
      </div>
      <div v-for="group in groups" :key="group.id" class="space-y-1 rounded-md border border-border/40 p-2 text-sm">
        <div class="flex items-center justify-between gap-2">
          <div class="min-w-0">
            <div class="truncate font-medium">
              {{ group.name }}
              <span v-if="group.parent_id" class="text-xs text-muted-foreground">({{ groupName(group.parent_id) }})</span>
            </div>
            <div class="truncate text-xs text-muted-foreground">{{ group.connection_ids.length }} {{ t("settings.identity.groupMembers") }}</div>
          </div>
          <div class="flex gap-1">
            <Button size="sm" variant="outline" class="h-7 px-1.5" @click="editGroupMembers(group)">
              <Pencil class="h-3.5 w-3.5" />
            </Button>
            <Button size="sm" variant="outline" class="h-7 px-1.5 text-destructive" @click="deleteGroup(group)">
              <Trash2 class="h-3.5 w-3.5" />
            </Button>
          </div>
        </div>
        <div v-if="editingGroupId === group.id" class="space-y-2">
          <div class="grid max-h-40 grid-cols-2 gap-1 overflow-auto text-xs sm:grid-cols-3">
            <span v-for="connection in connectionStore.connections" :key="connection.id" class="flex items-center gap-1.5">
              <input type="checkbox" :aria-label="connection.name" :checked="groupMembersDraft.includes(connection.id)" @change="toggleGroupMember(connection.id)" />
              <span class="truncate">{{ connection.name }}</span>
            </span>
          </div>
          <div class="flex justify-end">
            <Button size="sm" @click="saveGroupMembers(group)">{{ t("settings.identity.saveRole") }}</Button>
          </div>
        </div>
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

      <div v-if="roleFormOpen" class="space-y-2 rounded-md border border-border/40 p-2">
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
          <Button size="sm" variant="outline" @click="closeRoleEdit">{{ t("settings.identity.cancel") }}</Button>
          <Button size="sm" @click="saveRole">{{ t("settings.identity.saveRole") }}</Button>
        </div>
      </div>
    </div>

    <div v-if="roles.length > 0" class="space-y-1 rounded-lg border border-border/60 p-3">
      <div class="text-sm font-medium">{{ t("settings.identity.rolesTitle") }}</div>
      <div v-for="role in roles.filter((item) => item.builtin)" :key="role.code" class="flex items-start justify-between gap-2 text-xs text-muted-foreground">
        <div class="min-w-0">
          <span class="font-medium text-foreground">{{ role.name }}</span>
          ({{ role.code }}) — {{ role.description }}
        </div>
        <Button v-if="role.code !== 'admin'" size="sm" variant="outline" class="h-6 shrink-0 px-1.5" @click="startRoleEdit(role)">
          <Pencil class="h-3 w-3" />
        </Button>
      </div>
    </div>

    <div v-if="loading && !canLoad" class="flex justify-center py-4">
      <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
    </div>
    </template>

    <AccessInventory
      v-else-if="viewMode === 'inventory'"
      :key="inventoryVersion"
      :connections="connectionStore.connections"
      :groups="groups"
      :roles="roles"
      @open-user-access="openUserAccessById"
      @open-group="openGroupFromInventory"
    />

    <AccessGroups
      v-else-if="viewMode === 'groups'"
      ref="accessGroupsRef"
      :users="users"
      :roles="roles"
      :connection-groups="groups"
      :connections="connectionStore.connections"
      @changed="onAccessChanged"
    />



    <UserAccessDialog
      v-model:open="accessOpen"
      :user="accessUser"
      :roles="roles"
      :groups="groups"
      :connections="connectionStore.connections"
      :actor-permissions="actorPermissions"
      :actor-roles="actorRoles"
      :actor-id="props.actorId"
      @changed="onAccessChanged"
    />
  </div>
</template>

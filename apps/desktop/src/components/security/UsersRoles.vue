<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { LoaderCircle, RefreshCw, ShieldOff, UserPlus } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as usersApi from "@/lib/backend/users";
import type { LocalRole, LocalUser } from "@/lib/backend/users";

const { t } = useI18n();
const { toast } = useToast();

const users = ref<LocalUser[]>([]);
const roles = ref<LocalRole[]>([]);
const loading = ref(false);
const error = ref("");
const busyUserId = ref("");

const draftEmail = ref("");
const draftName = ref("");
const draftPassword = ref("");
const draftRole = ref("viewer");

const canLoad = computed(() => error.value === "" || users.value.length > 0);

async function refresh() {
  loading.value = true;
  error.value = "";
  try {
    users.value = await usersApi.listUsers();
    if (roles.value.length === 0) {
      roles.value = await usersApi.listRoles();
    }
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
    toast(t("settings.identity.sessionsRevoked"));
  } catch (revokeError) {
    toast(formatError(revokeError));
  } finally {
    busyUserId.value = "";
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
            <th class="w-48 px-3 py-2 text-right font-medium">{{ t("settings.identity.columnActions") }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="user in users" :key="user.id" class="border-t border-border/40">
            <td class="px-3 py-2">
              <div class="truncate font-medium">{{ user.display_name }}</div>
              <div class="truncate text-xs text-muted-foreground">{{ user.email }}</div>
            </td>
            <td class="px-3 py-2">
              <select v-if="!user.is_builtin" class="h-7 w-full rounded-md border border-input bg-background px-1.5 text-xs" :value="user.roles[0] ?? ''" :disabled="busyUserId === user.id" @change="changeRole(user, ($event.target as HTMLSelectElement).value)">
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
              <div class="flex justify-end gap-1.5">
                <Button variant="outline" size="sm" :disabled="busyUserId === user.id" @click="revokeSessions(user)">
                  <ShieldOff class="h-3.5 w-3.5" />
                </Button>
                <Button v-if="!user.is_builtin" variant="outline" size="sm" :disabled="busyUserId === user.id" @click="setStatus(user, user.status === 'active' ? 'disabled' : 'active')">
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

    <div v-if="roles.length > 0" class="space-y-1 rounded-lg border border-border/60 p-3">
      <div class="text-sm font-medium">{{ t("settings.identity.rolesTitle") }}</div>
      <div v-for="role in roles" :key="role.code" class="text-xs text-muted-foreground">
        <span class="font-medium text-foreground">{{ role.name }}</span>
        ({{ role.code }}) — {{ role.description }}
      </div>
    </div>

    <div v-if="loading && !canLoad" class="flex justify-center py-4">
      <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
    </div>
  </div>
</template>

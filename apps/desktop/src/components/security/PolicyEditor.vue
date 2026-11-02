<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { useI18n } from "vue-i18n";
import { LoaderCircle, RefreshCw, RotateCcw, Upload } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as policiesApi from "@/lib/backend/policies";
import type { EffectivePolicy, PolicyVersion } from "@/lib/backend/policies";
import { useConnectionStore } from "@/stores/connectionStore";

const { t } = useI18n();
const { toast } = useToast();
const connectionStore = useConnectionStore();

const scopeType = ref<"global" | "connection" | "database">("global");
const scopeConnection = ref("");
const scopeDatabase = ref("");
const versions = ref<PolicyVersion[]>([]);
const effective = ref<EffectivePolicy | null>(null);
const editor = ref('{\n  "rules": []\n}');
const note = ref("");
const loading = ref(false);
const publishing = ref(false);
const error = ref("");

const scopeId = computed(() => {
  if (scopeType.value === "global") return "";
  if (scopeType.value === "connection") return scopeConnection.value;
  return scopeConnection.value && scopeDatabase.value ? `${scopeConnection.value}::${scopeDatabase.value}` : "";
});

const scopeReady = computed(() => scopeType.value === "global" || (scopeType.value === "connection" && !!scopeConnection.value) || (scopeType.value === "database" && !!scopeConnection.value && !!scopeDatabase.value));

const builtinRules = computed(() => effective.value?.rules.filter((rule) => rule.builtin) ?? []);
const customRules = computed(() => effective.value?.rules.filter((rule) => !rule.builtin) ?? []);

async function refresh() {
  if (!scopeReady.value) return;
  loading.value = true;
  error.value = "";
  try {
    versions.value = await policiesApi.listPolicies(scopeType.value, scopeId.value);
    effective.value = await policiesApi.effectivePolicy();
  } catch (loadError) {
    error.value = formatError(loadError);
    versions.value = [];
  } finally {
    loading.value = false;
  }
}

async function publish() {
  if (!scopeReady.value) {
    toast(t("settings.policies.scopeRequired"));
    return;
  }
  let document: unknown;
  try {
    document = JSON.parse(editor.value);
  } catch {
    toast(t("settings.policies.invalidJson"));
    return;
  }
  publishing.value = true;
  try {
    await policiesApi.publishPolicy({
      scope_type: scopeType.value,
      scope_id: scopeType.value === "global" ? "" : scopeId.value,
      document,
      note: note.value,
    });
    note.value = "";
    await refresh();
  } catch (publishError) {
    toast(formatError(publishError));
  } finally {
    publishing.value = false;
  }
}

async function rollback(version: PolicyVersion) {
  try {
    await policiesApi.rollbackPolicy({
      scope_type: version.scope_type,
      scope_id: version.scope_id,
      version: version.version,
      note: `rollback to v${version.version}`,
    });
    await refresh();
  } catch (rollbackError) {
    toast(formatError(rollbackError));
  }
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
        <h3 class="text-base font-medium">{{ t("settings.policies.title") }}</h3>
        <p class="text-sm text-muted-foreground">{{ t("settings.policies.description") }}</p>
      </div>
      <Button variant="outline" size="sm" class="gap-1.5" :disabled="loading" @click="refresh">
        <RefreshCw :class="['h-3.5 w-3.5', loading ? 'animate-spin' : '']" />
        {{ t("settings.audit.refresh") }}
      </Button>
    </div>

    <div class="flex flex-wrap items-center gap-2">
      <select v-model="scopeType" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="refresh">
        <option value="global">{{ t("settings.identity.scopeGlobal") }}</option>
        <option value="connection">{{ t("settings.identity.scopeConnection") }}</option>
        <option value="database">{{ t("settings.identity.scopeDatabase") }}</option>
      </select>
      <select v-if="scopeType !== 'global'" v-model="scopeConnection" class="h-8 max-w-48 rounded-md border border-input bg-background px-2 text-sm" @change="refresh">
        <option value="">{{ t("settings.identity.scopeSelect") }}</option>
        <option v-for="connection in connectionStore.connections" :key="connection.id" :value="connection.id">
          {{ connection.name }}
        </option>
      </select>
      <Input v-if="scopeType === 'database'" v-model="scopeDatabase" class="h-8 w-36" :placeholder="t('settings.identity.scopeDatabaseName')" @blur="refresh" />
      <Badge v-if="effective" variant="outline" class="font-mono text-[10px]" :title="effective.policy_bundle_hash"> {{ effective.policy_bundle_hash.slice(0, 12) }}… </Badge>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
      {{ error }}
    </p>

    <div class="space-y-2 rounded-lg border border-border/60 p-3">
      <div class="text-sm font-medium">{{ t("settings.policies.publishTitle") }}</div>
      <p class="text-xs text-muted-foreground">{{ t("settings.policies.publishHint") }}</p>
      <textarea v-model="editor" spellcheck="false" class="h-48 w-full rounded-md border border-input bg-background p-2 font-mono text-xs" :aria-label="t('settings.policies.publishTitle')"></textarea>
      <div class="flex flex-wrap items-center gap-2">
        <Input v-model="note" class="h-8 flex-1" :placeholder="t('settings.policies.note')" />
        <Button size="sm" class="gap-1.5" :disabled="publishing || !scopeReady" @click="publish">
          <Upload class="h-3.5 w-3.5" />
          {{ t("settings.policies.publish") }}
        </Button>
      </div>
    </div>

    <div class="space-y-2">
      <div class="text-sm font-medium">{{ t("settings.policies.versions") }}</div>
      <p v-if="versions.length === 0 && !loading" class="text-xs text-muted-foreground">
        {{ t("settings.policies.noVersions") }}
      </p>
      <div v-for="version in versions" :key="version.id || `${version.scope_type}-${version.version}`" class="flex items-center justify-between gap-2 rounded-md border border-border/40 p-2 text-sm">
        <div class="min-w-0">
          <div class="truncate">
            <span class="font-medium">v{{ version.version }}</span>
            <span class="text-xs text-muted-foreground"> · {{ version.created_by || "—" }} · {{ formatTime(version.created_at_ms) }}</span>
          </div>
          <div class="truncate text-xs text-muted-foreground">{{ version.note || "—" }}</div>
        </div>
        <Button size="sm" variant="outline" class="h-7 gap-1 px-1.5 text-xs" @click="rollback(version)">
          <RotateCcw class="h-3.5 w-3.5" />
          {{ t("settings.policies.rollback") }}
        </Button>
      </div>
    </div>

    <div v-if="effective" class="space-y-2 rounded-lg border border-border/60 p-3">
      <div class="text-sm font-medium">{{ t("settings.policies.effective") }}</div>
      <div v-for="rule in customRules" :key="rule.id" class="text-xs">
        <Badge variant="outline" :class="rule.effect === 'block' ? 'text-destructive' : ''">{{ rule.effect }}</Badge>
        <span class="ml-1 font-mono">{{ rule.id }}</span>
        <span class="ml-1 text-muted-foreground">{{ rule.message }}</span>
      </div>
      <details class="text-xs text-muted-foreground">
        <summary class="cursor-pointer">{{ t("settings.policies.builtinRules") }} ({{ builtinRules.length }})</summary>
        <div v-for="rule in builtinRules" :key="rule.id" class="mt-1">
          <span class="font-mono">{{ rule.id }}</span> · {{ rule.effect }}
        </div>
      </details>
    </div>

    <div v-if="loading" class="flex justify-center py-2">
      <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
    </div>
  </div>
</template>

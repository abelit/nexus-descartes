<script setup lang="ts">
import { computed, onMounted, reactive, ref } from "vue";
import { useI18n } from "vue-i18n";
import { FileJson, ListChecks, LoaderCircle, Pencil, Plus, RefreshCw, RotateCcw, Trash2, Upload } from "@lucide/vue";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { useToast } from "@/composables/useToast";
import { formatError } from "@/lib/backend/errorUtils";
import * as approvalsApi from "@/lib/backend/approvals";
import type { ApprovalTemplate } from "@/lib/backend/approvals";
import * as policiesApi from "@/lib/backend/policies";
import type {
  EffectivePolicy,
  EffectiveRule,
  PolicyDocument,
  PolicyEffect,
  PolicyRule,
  PolicyRuleMatch,
  PolicyVersion,
} from "@/lib/backend/policies";
import { useConnectionStore } from "@/stores/connectionStore";

type Mode = "form" | "json";

interface EditableRule {
  id: string;
  enabled: boolean;
  priority: number;
  action: PolicyEffect;
  message: string;
  approval_template_id: string;
  match: {
    statement_types: string[];
    production_only: boolean;
    requires_where: boolean | null;
    unbounded_only: boolean;
    databases: string[];
    tables: string[];
  };
}

const { t } = useI18n();
const { toast } = useToast();
const connectionStore = useConnectionStore();

const scopeType = ref<"global" | "connection" | "database">("global");
const scopeConnection = ref("");
const scopeDatabase = ref("");
const versions = ref<PolicyVersion[]>([]);
const effective = ref<EffectivePolicy | null>(null);
const mode = ref<Mode>("form");
const rules = ref<EditableRule[]>([]);
const editor = ref("{\n  \"rules\": []\n}");
const jsonError = ref("");
const note = ref("");
const loading = ref(false);
const publishing = ref(false);
const error = ref("");

const ruleDialogOpen = ref(false);
const editingIndex = ref<number | null>(null);
const ruleDraft = reactive<EditableRule>(emptyRule());
const ruleError = ref("");
const deleteOpen = ref(false);
const deleteIndex = ref<number | null>(null);
const approvalTemplates = ref<ApprovalTemplate[]>([]);

const STATEMENT_TYPES = ["select", "dml", "ddl", "truncate", "privilege", "transaction"];
const EFFECTS: PolicyEffect[] = ["allow", "warn", "require_approval", "block"];

const scopeId = computed(() => {
  if (scopeType.value === "global") return "";
  if (scopeType.value === "connection") return scopeConnection.value;
  return scopeConnection.value && scopeDatabase.value ? `${scopeConnection.value}::${scopeDatabase.value}` : "";
});

const scopeReady = computed(
  () =>
    scopeType.value === "global" ||
    (scopeType.value === "connection" && !!scopeConnection.value) ||
    (scopeType.value === "database" && !!scopeConnection.value && !!scopeDatabase.value),
);

const builtinRules = computed(() => effective.value?.rules.filter((rule) => rule.builtin) ?? []);
const customEffectiveRules = computed(() => effective.value?.rules.filter((rule) => !rule.builtin) ?? []);
const availableApprovalTemplates = computed(() =>
  approvalTemplates.value.filter(
    (template) =>
      template.scope_type === "global" ||
      (scopeType.value !== "global" && template.scope_type === "connection" && template.scope_id === scopeConnection.value),
  ),
);

function templateLabel(templateId: string): string {
  return approvalTemplates.value.find((template) => template.id === templateId)?.name || templateId;
}

const ruleDatabasesText = computed({
  get: () => ruleDraft.match.databases.join(", "),
  set: (value: string) => {
    ruleDraft.match.databases = value.split(",").map((item) => item.trim()).filter(Boolean);
  },
});

const ruleTablesText = computed({
  get: () => ruleDraft.match.tables.join(", "),
  set: (value: string) => {
    ruleDraft.match.tables = value.split(",").map((item) => item.trim()).filter(Boolean);
  },
});

const requiresWhereValue = computed({
  get: () => (ruleDraft.match.requires_where === true ? "required" : ruleDraft.match.requires_where === false ? "forbidden" : "any"),
  set: (value: string) => {
    ruleDraft.match.requires_where = value === "required" ? true : value === "forbidden" ? false : null;
  },
});

const templates = computed(() => [
  { key: "prod_ddl_approval", label: t("settings.policies.templateProdDdlApproval"), rule: templateRule("custom.prod-ddl-approval", "require_approval", t("settings.policies.templateProdDdlApprovalMessage"), { statement_types: ["ddl"], production_only: true }, 100) },
  { key: "block_unbounded_dml", label: t("settings.policies.templateBlockUnboundedDml"), rule: templateRule("custom.block-unbounded-dml", "block", t("settings.policies.templateBlockUnboundedDmlMessage"), { statement_types: ["dml"], unbounded_only: true }, 120) },
  { key: "privilege_approval", label: t("settings.policies.templatePrivilegeApproval"), rule: templateRule("custom.privilege-approval", "require_approval", t("settings.policies.templatePrivilegeApprovalMessage"), { statement_types: ["privilege"], production_only: true }, 105) },
  { key: "warn_truncate", label: t("settings.policies.templateWarnTruncate"), rule: templateRule("custom.warn-truncate", "warn", t("settings.policies.templateWarnTruncateMessage"), { statement_types: ["truncate"] }, 50) },
]);

function emptyRule(): EditableRule {
  return {
    id: "",
    enabled: true,
    priority: 100,
    action: "warn",
    message: "",
    approval_template_id: "",
    match: { statement_types: [], production_only: false, requires_where: null, unbounded_only: false, databases: [], tables: [] },
  };
}

function templateRule(
  id: string,
  action: PolicyEffect,
  message: string,
  match: Partial<EditableRule["match"]>,
  priority: number,
): EditableRule {
  return {
    id,
    enabled: true,
    priority,
    action,
    message,
    approval_template_id: "",
    match: {
      statement_types: match.statement_types ?? [],
      production_only: match.production_only ?? false,
      requires_where: match.requires_where ?? null,
      unbounded_only: match.unbounded_only ?? false,
      databases: match.databases ?? [],
      tables: match.tables ?? [],
    },
  };
}

function normalizeRule(raw: PolicyRule | Record<string, unknown>): EditableRule {
  const value = raw as Record<string, unknown>;
  const match = (value.match ?? {}) as Record<string, unknown>;
  const action = EFFECTS.includes(value.action as PolicyEffect) ? (value.action as PolicyEffect) : "warn";
  return {
    id: typeof value.id === "string" ? value.id : "",
    enabled: value.enabled !== false,
    priority: typeof value.priority === "number" ? value.priority : 0,
    action,
    message: typeof value.message === "string" ? value.message : "",
    approval_template_id: typeof value.approval_template_id === "string" ? value.approval_template_id : "",
    match: {
      statement_types: Array.isArray(match.statement_types) ? match.statement_types.map(String) : [],
      production_only: match.production_only === true,
      requires_where: match.requires_where === true ? true : match.requires_where === false ? false : null,
      unbounded_only: match.unbounded_only === true,
      databases: Array.isArray(match.databases) ? match.databases.map(String) : [],
      tables: Array.isArray(match.tables) ? match.tables.map(String) : [],
    },
  };
}

function serializeRule(rule: EditableRule): PolicyRule {
  const match: PolicyRuleMatch = {};
  if (rule.match.statement_types.length) match.statement_types = [...rule.match.statement_types];
  if (rule.match.production_only) match.production_only = true;
  if (rule.match.requires_where !== null) match.requires_where = rule.match.requires_where;
  if (rule.match.unbounded_only) match.unbounded_only = true;
  if (rule.match.databases.length) match.databases = [...rule.match.databases];
  if (rule.match.tables.length) match.tables = [...rule.match.tables];
  return {
    id: rule.id.trim(),
    enabled: rule.enabled,
    priority: Number.isFinite(rule.priority) ? Math.trunc(rule.priority) : 0,
    action: rule.action,
    message: rule.message.trim(),
    ...(rule.action === "require_approval" && rule.approval_template_id.trim()
      ? { approval_template_id: rule.approval_template_id.trim() }
      : {}),
    match,
  };
}

function documentFromRules(): PolicyDocument {
  return { rules: rules.value.map(serializeRule) };
}

function loadDocument(document: PolicyDocument) {
  const list = Array.isArray(document?.rules) ? document.rules : [];
  rules.value = list.map(normalizeRule);
  editor.value = JSON.stringify(documentFromRules(), null, 2);
  jsonError.value = "";
}

function loadLatestDocument() {
  const latest = versions.value[0];
  loadDocument(latest?.document ?? { rules: [] });
}

function validateRules(list: EditableRule[]): string | null {
  const ids = new Set<string>();
  for (const rule of list) {
    if (!rule.id.trim()) return t("settings.policies.ruleIdRequired");
    if (!rule.message.trim()) return t("settings.policies.ruleMessageRequired", { id: rule.id });
    if (!EFFECTS.includes(rule.action)) return t("settings.policies.invalidDocument");
    if (ids.has(rule.id.trim())) return t("settings.policies.duplicateRuleId", { id: rule.id });
    ids.add(rule.id.trim());
  }
  return null;
}

async function refresh(loadLatest = true) {
  if (!scopeReady.value) return;
  loading.value = true;
  error.value = "";
  try {
    versions.value = await policiesApi.listPolicies(scopeType.value, scopeId.value);
    effective.value = await policiesApi.effectivePolicy();
    try {
      approvalTemplates.value = await approvalsApi.listApprovalTemplates();
    } catch {
      approvalTemplates.value = [];
    }
    if (loadLatest) loadLatestDocument();
  } catch (loadError) {
    error.value = formatError(loadError);
    versions.value = [];
  } finally {
    loading.value = false;
  }
}

function switchMode(next: Mode) {
  if (next === mode.value) return;
  if (next === "json") {
    editor.value = JSON.stringify(documentFromRules(), null, 2);
    jsonError.value = "";
    mode.value = "json";
    return;
  }
  if (applyJson(false)) mode.value = "form";
}

function applyJson(notify = true): boolean {
  try {
    const parsed = JSON.parse(editor.value) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("document");
    const record = parsed as Record<string, unknown>;
    if (record.rules !== undefined && !Array.isArray(record.rules)) throw new Error("rules");
    const document: PolicyDocument = { rules: (record.rules as PolicyRule[] | undefined) ?? [] };
    loadDocument(document);
    jsonError.value = "";
    if (notify) toast(t("settings.policies.jsonApplied"));
    return true;
  } catch {
    jsonError.value = t("settings.policies.invalidJson");
    return false;
  }
}

function formatJson() {
  try {
    editor.value = JSON.stringify(JSON.parse(editor.value), null, 2);
    jsonError.value = "";
  } catch {
    jsonError.value = t("settings.policies.invalidJson");
  }
}

async function publish() {
  if (!scopeReady.value) {
    toast(t("settings.policies.scopeRequired"));
    return;
  }
  let document: PolicyDocument;
  if (mode.value === "json") {
    try {
      const parsed = JSON.parse(editor.value) as Record<string, unknown>;
      if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.rules)) {
        toast(t("settings.policies.invalidJson"));
        return;
      }
      document = { rules: (parsed.rules as PolicyRule[]).map(normalizeRule).map(serializeRule) };
    } catch {
      toast(t("settings.policies.invalidJson"));
      return;
    }
  } else {
    document = documentFromRules();
  }
  const normalized = document.rules.map((rule) => normalizeRule(rule));
  const validation = validateRules(normalized);
  if (validation) {
    toast(validation);
    return;
  }
  publishing.value = true;
  try {
    await policiesApi.publishPolicy({
      scope_type: scopeType.value,
      scope_id: scopeType.value === "global" ? "" : scopeId.value,
      document: { rules: normalized.map(serializeRule) },
      note: note.value,
    });
    note.value = "";
    await refresh(true);
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
    await refresh(true);
  } catch (rollbackError) {
    toast(formatError(rollbackError));
  }
}

function loadVersion(version: PolicyVersion) {
  loadDocument(version.document);
  if (mode.value === "json") {
    editor.value = JSON.stringify(documentFromRules(), null, 2);
  }
  toast(t("settings.policies.versionLoaded", { version: version.version }));
}

function openAddRule(template?: EditableRule) {
  editingIndex.value = null;
  Object.assign(ruleDraft, JSON.parse(JSON.stringify(template ?? emptyRule())));
  ruleError.value = "";
  ruleDialogOpen.value = true;
}

function openEditRule(index: number) {
  editingIndex.value = index;
  Object.assign(ruleDraft, JSON.parse(JSON.stringify(rules.value[index])));
  ruleError.value = "";
  ruleDialogOpen.value = true;
}

function openOverrideRule(rule: EffectiveRule) {
  const existing = rules.value.findIndex((candidate) => candidate.id === rule.id);
  if (existing >= 0) {
    openEditRule(existing);
    return;
  }
  openAddRule(
    templateRule(
      rule.id,
      rule.effect as PolicyEffect,
      rule.message,
      {
        statement_types: rule.match.statement_types ?? [],
        production_only: rule.match.production_only ?? false,
        requires_where: rule.match.requires_where ?? null,
        unbounded_only: rule.match.unbounded_only ?? false,
        databases: rule.match.databases ?? [],
        tables: rule.match.tables ?? [],
      },
      rule.priority,
    ),
  );
}

function addFromTemplate(event: Event) {
  const value = (event.target as HTMLSelectElement).value;
  (event.target as HTMLSelectElement).value = "";
  const template = templates.value.find((item) => item.key === value);
  if (!template) return;
  const existing = rules.value.findIndex((rule) => rule.id === template.rule.id);
  if (existing >= 0) {
    openEditRule(existing);
    return;
  }
  openAddRule(template.rule);
}

function toggleStatementType(type: string) {
  const values = ruleDraft.match.statement_types;
  ruleDraft.match.statement_types = values.includes(type) ? values.filter((item) => item !== type) : [...values, type];
}

function saveRule() {
  if (!ruleDraft.id.trim()) {
    ruleError.value = t("settings.policies.ruleIdRequired");
    return;
  }
  if (!ruleDraft.message.trim()) {
    ruleError.value = t("settings.policies.ruleMessageRequired", { id: ruleDraft.id });
    return;
  }
  const duplicate = rules.value.some((rule, index) => index !== editingIndex.value && rule.id.trim() === ruleDraft.id.trim());
  if (duplicate) {
    ruleError.value = t("settings.policies.duplicateRuleId", { id: ruleDraft.id });
    return;
  }
  const copy = JSON.parse(JSON.stringify(ruleDraft)) as EditableRule;
  if (copy.action !== "require_approval") copy.approval_template_id = "";
  if (editingIndex.value === null) rules.value = [...rules.value, copy];
  else rules.value = rules.value.map((rule, index) => (index === editingIndex.value ? copy : rule));
  ruleDialogOpen.value = false;
}

function askDeleteRule(index: number) {
  deleteIndex.value = index;
  deleteOpen.value = true;
}

function confirmDeleteRule() {
  if (deleteIndex.value === null) return;
  rules.value = rules.value.filter((_, index) => index !== deleteIndex.value);
  deleteIndex.value = null;
  deleteOpen.value = false;
}

function effectClass(effect: string): string {
  switch (effect) {
    case "block":
      return "border-destructive/50 text-destructive";
    case "require_approval":
      return "border-amber-500/50 text-amber-600 dark:text-amber-400";
    case "warn":
      return "border-sky-500/50 text-sky-600 dark:text-sky-400";
    default:
      return "border-border text-muted-foreground";
  }
}

function effectLabel(effect: string): string {
  switch (effect) {
    case "allow":
      return t("settings.policies.effectAllow");
    case "warn":
      return t("settings.policies.effectWarn");
    case "require_approval":
      return t("settings.policies.effectRequireApproval");
    case "block":
      return t("settings.policies.effectBlock");
    default:
      return effect;
  }
}

function conditionSummary(rule: EditableRule): string {
  const parts: string[] = [];
  parts.push(rule.match.statement_types.length ? rule.match.statement_types.join(", ") : t("settings.policies.anyStatement"));
  if (rule.match.production_only) parts.push(t("settings.policies.productionOnlyShort"));
  if (rule.match.unbounded_only) parts.push(t("settings.policies.unboundedShort"));
  if (rule.match.requires_where === true) parts.push(t("settings.policies.requiresWhereRequired"));
  if (rule.match.requires_where === false) parts.push(t("settings.policies.requiresWhereForbidden"));
  if (rule.match.databases.length) parts.push(rule.match.databases.join(", "));
  if (rule.match.tables.length) parts.push(rule.match.tables.join(", "));
  return parts.join(" · ");
}

function formatTime(ms: number): string {
  return new Date(ms).toLocaleString();
}

onMounted(() => {
  void refresh(true);
});
</script>

<template>
  <div class="space-y-4">
    <div class="flex items-start justify-between gap-3">
      <div class="space-y-1">
        <h3 class="text-base font-medium">{{ t("settings.policies.title") }}</h3>
        <p class="text-sm text-muted-foreground">{{ t("settings.policies.description") }}</p>
      </div>
      <Button variant="outline" size="sm" class="gap-1.5" :disabled="loading || !scopeReady" @click="refresh(true)">
        <RefreshCw :class="['h-3.5 w-3.5', loading ? 'animate-spin' : '']" />
        {{ t("settings.audit.refresh") }}
      </Button>
    </div>

    <div class="flex flex-wrap items-center gap-2">
      <select v-model="scopeType" class="h-8 rounded-md border border-input bg-background px-2 text-sm" @change="refresh(true)">
        <option value="global">{{ t("settings.identity.scopeGlobal") }}</option>
        <option value="connection">{{ t("settings.identity.scopeConnection") }}</option>
        <option value="database">{{ t("settings.identity.scopeDatabase") }}</option>
      </select>
      <select v-if="scopeType !== 'global'" v-model="scopeConnection" class="h-8 max-w-48 rounded-md border border-input bg-background px-2 text-sm" @change="refresh(true)">
        <option value="">{{ t("settings.identity.scopeSelect") }}</option>
        <option v-for="connection in connectionStore.connections" :key="connection.id" :value="connection.id">{{ connection.name }}</option>
      </select>
      <Input v-if="scopeType === 'database'" v-model="scopeDatabase" class="h-8 w-36" :placeholder="t('settings.identity.scopeDatabaseName')" @keyup.enter="refresh(true)" @blur="refresh(true)" />
      <Badge v-if="effective" variant="outline" class="font-mono text-[10px]" :title="effective.policy_bundle_hash">
        {{ effective.policy_bundle_hash.slice(0, 12) }}…
      </Badge>
    </div>

    <p v-if="error" class="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{{ error }}</p>

    <div class="flex items-center gap-1 border-b border-border/60">
      <button type="button" class="flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm" :class="mode === 'form' ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground'" @click="switchMode('form')">
        <ListChecks class="h-3.5 w-3.5" />
        {{ t("settings.policies.formMode") }}
      </button>
      <button type="button" class="flex items-center gap-1.5 border-b-2 px-3 py-2 text-sm" :class="mode === 'json' ? 'border-primary font-medium text-foreground' : 'border-transparent text-muted-foreground'" @click="switchMode('json')">
        <FileJson class="h-3.5 w-3.5" />
        {{ t("settings.policies.jsonMode") }}
      </button>
    </div>

    <div class="space-y-3 rounded-lg border border-border/60 p-3">
      <template v-if="mode === 'form'">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <div>
            <div class="text-sm font-medium">{{ t("settings.policies.draftRules") }}</div>
            <p class="text-xs text-muted-foreground">{{ t("settings.policies.draftRulesHint") }}</p>
          </div>
          <div class="flex flex-wrap items-center gap-2">
            <select class="h-8 rounded-md border border-input bg-background px-2 text-sm" :aria-label="t('settings.policies.addFromTemplate')" @change="addFromTemplate">
              <option value="">{{ t("settings.policies.addFromTemplate") }}</option>
              <option v-for="template in templates" :key="template.key" :value="template.key">{{ template.label }}</option>
            </select>
            <Button size="sm" class="gap-1" @click="openAddRule()">
              <Plus class="h-3.5 w-3.5" />
              {{ t("settings.policies.addRule") }}
            </Button>
          </div>
        </div>

        <p v-if="rules.length === 0" class="rounded-md border border-dashed border-border/60 p-3 text-xs text-muted-foreground">
          {{ t("settings.policies.noDraftRules") }}
        </p>
        <div v-else class="space-y-2">
          <div v-for="(rule, index) in rules" :key="`${rule.id}-${index}`" class="space-y-1 rounded-md border border-border/50 px-2 py-2">
            <div class="flex flex-wrap items-center gap-2">
              <Badge variant="outline" :class="effectClass(rule.action)">{{ effectLabel(rule.action) }}</Badge>
              <span class="font-mono text-xs font-medium">{{ rule.id }}</span>
              <Badge v-if="!rule.enabled" variant="outline">{{ t("settings.policies.disabled") }}</Badge>
              <span class="text-xs text-muted-foreground">#{{ rule.priority }}</span>
              <Badge v-if="rule.approval_template_id" variant="outline" :title="rule.approval_template_id">
                {{ t("settings.policies.ruleApprovalTemplateBadge", { template: templateLabel(rule.approval_template_id) }) }}
              </Badge>
              <span class="ml-auto flex gap-1">
                <Button size="sm" variant="outline" class="h-6 px-1.5" :title="t('settings.policies.editRule')" @click="openEditRule(index)">
                  <Pencil class="h-3 w-3" />
                </Button>
                <Button size="sm" variant="outline" class="h-6 px-1.5 text-destructive" :title="t('settings.policies.deleteRule')" @click="askDeleteRule(index)">
                  <Trash2 class="h-3 w-3" />
                </Button>
              </span>
            </div>
            <div class="text-xs text-muted-foreground">{{ conditionSummary(rule) }}</div>
            <div class="text-xs">{{ rule.message }}</div>
          </div>
        </div>
      </template>

      <template v-else>
        <p class="text-xs text-muted-foreground">{{ t("settings.policies.jsonHint") }}</p>
        <textarea v-model="editor" spellcheck="false" class="h-72 w-full rounded-md border border-input bg-background p-2 font-mono text-xs" :aria-label="t('settings.policies.jsonMode')"></textarea>
        <p v-if="jsonError" class="text-xs text-destructive">{{ jsonError }}</p>
        <div class="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="outline" @click="formatJson">{{ t("settings.policies.formatJson") }}</Button>
          <Button size="sm" variant="outline" @click="applyJson(true)">{{ t("settings.policies.applyJson") }}</Button>
          <span class="text-xs text-muted-foreground">{{ t("settings.policies.jsonApplyHint") }}</span>
        </div>
        <details class="text-xs text-muted-foreground">
          <summary class="cursor-pointer">{{ t("settings.policies.exampleTitle") }}</summary>
          <pre class="mt-2 max-h-64 overflow-auto rounded-md bg-muted/40 p-2 font-mono">{{ `{\n  "rules": [\n    {\n      "id": "custom.prod-ddl-approval",\n      "enabled": true,\n      "priority": 100,
      "approval_template_id": "<approval-template-id>",\n      "match": {\n        "statement_types": ["ddl"],\n        "production_only": true\n      },\n      "action": "require_approval",\n      "message": "DDL on production requires approval"\n    }\n  ]\n}` }}</pre>
        </details>
      </template>

      <div class="flex flex-wrap items-center gap-2 border-t border-border/50 pt-3">
        <Input v-model="note" class="h-8 flex-1" :placeholder="t('settings.policies.note')" />
        <Button size="sm" class="gap-1.5" :disabled="publishing || !scopeReady" @click="publish">
          <Upload class="h-3.5 w-3.5" />
          {{ t("settings.policies.publish") }}
        </Button>
      </div>
    </div>

    <div v-if="effective" class="space-y-2 rounded-lg border border-border/60 p-3">
      <div class="text-sm font-medium">{{ t("settings.policies.builtinRules") }}</div>
      <p class="text-xs text-muted-foreground">{{ t("settings.policies.builtinOverrideHint") }}</p>
      <div v-for="rule in builtinRules" :key="rule.id" class="flex flex-wrap items-center gap-2 text-xs">
        <Badge variant="outline" :class="effectClass(rule.effect)">{{ effectLabel(rule.effect) }}</Badge>
        <span class="font-mono">{{ rule.id }}</span>
        <span class="min-w-0 flex-1 truncate text-muted-foreground">{{ rule.message }}</span>
        <Button size="sm" variant="outline" class="h-6 px-1.5 text-xs" @click="openOverrideRule(rule)">{{ t("settings.policies.override") }}</Button>
      </div>
      <details v-if="customEffectiveRules.length" class="text-xs text-muted-foreground">
        <summary class="cursor-pointer">{{ t("settings.policies.effectiveCustom", { count: customEffectiveRules.length }) }}</summary>
        <div v-for="rule in customEffectiveRules" :key="rule.id" class="mt-1">
          <span class="font-mono">{{ rule.id }}</span> · {{ rule.effect }} · {{ rule.message }}
        </div>
      </details>
    </div>

    <div class="space-y-2">
      <div class="text-sm font-medium">{{ t("settings.policies.versions") }}</div>
      <p v-if="versions.length === 0 && !loading" class="text-xs text-muted-foreground">{{ t("settings.policies.noVersions") }}</p>
      <div v-for="version in versions" :key="version.id || `${version.scope_type}-${version.version}`" class="flex items-center justify-between gap-2 rounded-md border border-border/40 p-2 text-sm">
        <div class="min-w-0">
          <div class="truncate">
            <span class="font-medium">v{{ version.version }}</span>
            <span class="text-xs text-muted-foreground"> · {{ version.created_by || "—" }} · {{ formatTime(version.created_at_ms) }}</span>
          </div>
          <div class="truncate text-xs text-muted-foreground">{{ version.note || "—" }}</div>
        </div>
        <div class="flex shrink-0 gap-1">
          <Button size="sm" variant="outline" class="h-7 px-1.5 text-xs" :title="t('settings.policies.loadVersion')" @click="loadVersion(version)">
            {{ t("settings.policies.loadVersion") }}
          </Button>
          <Button size="sm" variant="outline" class="h-7 gap-1 px-1.5 text-xs" @click="rollback(version)">
            <RotateCcw class="h-3.5 w-3.5" />
            {{ t("settings.policies.rollback") }}
          </Button>
        </div>
      </div>
    </div>

    <div v-if="loading" class="flex justify-center py-2">
      <LoaderCircle class="h-4 w-4 animate-spin text-muted-foreground" />
    </div>

    <Dialog :open="ruleDialogOpen" @update:open="(value) => !value && (ruleDialogOpen = false)">
      <DialogContent class="max-h-[calc(var(--dbx-viewport-height)-2rem)] w-full max-w-2xl overflow-y-auto">
        <DialogTitle>{{ editingIndex === null ? t("settings.policies.addRule") : t("settings.policies.editRule") }}</DialogTitle>
        <div class="space-y-3 text-sm">
          <div class="grid gap-2 sm:grid-cols-2">
            <label class="space-y-1 text-xs text-muted-foreground">
              <span>{{ t("settings.policies.ruleId") }}</span>
              <Input v-model="ruleDraft.id" class="h-8 font-mono" @input="ruleError = ''" />
            </label>
            <label class="space-y-1 text-xs text-muted-foreground">
              <span>{{ t("settings.policies.rulePriority") }}</span>
              <Input v-model.number="ruleDraft.priority" type="number" class="h-8" />
            </label>
            <label class="space-y-1 text-xs text-muted-foreground">
              <span>{{ t("settings.policies.ruleEffect") }}</span>
              <select v-model="ruleDraft.action" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
                <option v-for="effect in EFFECTS" :key="effect" :value="effect">{{ effectLabel(effect) }}</option>
              </select>
            </label>
            <label class="flex items-center gap-2 pt-5 text-xs text-muted-foreground">
              <input v-model="ruleDraft.enabled" type="checkbox" />
              {{ t("settings.policies.ruleEnabled") }}
            </label>
          </div>
          <div v-if="ruleDraft.action === 'require_approval'" class="space-y-1 text-xs text-muted-foreground">
            <span>{{ t("settings.policies.ruleApprovalTemplate") }}</span>
            <select v-model="ruleDraft.approval_template_id" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
              <option value="">{{ t("settings.policies.ruleApprovalTemplateDefault") }}</option>
              <option v-for="template in availableApprovalTemplates" :key="template.id" :value="template.id">
                {{ template.name }} · {{ template.scope_type === "global" ? t("settings.identity.scopeGlobal") : template.scope_id }}
              </option>
            </select>
            <p class="text-[11px]">{{ t("settings.policies.ruleApprovalTemplateHint") }}</p>
          </div>
          <div class="space-y-1">
            <div class="text-xs text-muted-foreground">{{ t("settings.policies.ruleStatementTypes") }}</div>
            <div class="grid grid-cols-2 gap-1 text-xs sm:grid-cols-3">
              <label v-for="type in STATEMENT_TYPES" :key="type" class="flex items-center gap-1.5">
                <input type="checkbox" :checked="ruleDraft.match.statement_types.includes(type)" @change="toggleStatementType(type)" />
                {{ t(`settings.policies.statement_${type}`) }}
              </label>
            </div>
            <p class="text-[11px] text-muted-foreground">{{ t("settings.policies.ruleStatementTypesHint") }}</p>
          </div>
          <div class="grid gap-2 sm:grid-cols-2">
            <label class="flex items-center gap-2 text-xs text-muted-foreground">
              <input v-model="ruleDraft.match.production_only" type="checkbox" />
              {{ t("settings.policies.ruleProductionOnly") }}
            </label>
            <label class="flex items-center gap-2 text-xs text-muted-foreground">
              <input v-model="ruleDraft.match.unbounded_only" type="checkbox" />
              {{ t("settings.policies.ruleUnboundedOnly") }}
            </label>
          </div>
          <div class="grid gap-2 sm:grid-cols-2">
            <label class="space-y-1 text-xs text-muted-foreground">
              <span>{{ t("settings.policies.ruleRequiresWhere") }}</span>
              <select v-model="requiresWhereValue" class="h-8 w-full rounded-md border border-input bg-background px-2 text-sm">
                <option value="any">{{ t("settings.policies.requiresWhereAny") }}</option>
                <option value="required">{{ t("settings.policies.requiresWhereRequired") }}</option>
                <option value="forbidden">{{ t("settings.policies.requiresWhereForbidden") }}</option>
              </select>
            </label>
            <label class="space-y-1 text-xs text-muted-foreground">
              <span>{{ t("settings.policies.ruleDatabases") }}</span>
              <Input v-model="ruleDatabasesText" class="h-8" :placeholder="t('settings.policies.ruleDatabasesPlaceholder')" />
              <span class="text-[11px]">{{ t("settings.policies.ruleDatabasesHint") }}</span>
            </label>
            <label class="space-y-1 text-xs text-muted-foreground">
              <span>{{ t("settings.policies.ruleTables") }}</span>
              <Input v-model="ruleTablesText" class="h-8" :placeholder="t('settings.policies.ruleTablesPlaceholder')" />
              <span class="text-[11px]">{{ t("settings.policies.ruleTablesHint") }}</span>
            </label>
          </div>
          <label class="block space-y-1 text-xs text-muted-foreground">
            <span>{{ t("settings.policies.ruleMessage") }}</span>
            <textarea v-model="ruleDraft.message" class="min-h-16 w-full rounded-md border border-input bg-background p-2 text-sm" :placeholder="t('settings.policies.ruleMessagePlaceholder')"></textarea>
          </label>
          <p v-if="ruleError" class="text-xs text-destructive">{{ ruleError }}</p>
        </div>
        <div class="mt-3 flex justify-end gap-2">
          <Button variant="outline" size="sm" @click="ruleDialogOpen = false">{{ t("settings.identity.cancel") }}</Button>
          <Button size="sm" @click="saveRule">{{ t("settings.policies.saveRule") }}</Button>
        </div>
      </DialogContent>
    </Dialog>

    <Dialog :open="deleteOpen" @update:open="(value) => !value && (deleteOpen = false)">
      <DialogContent class="sm:max-w-md">
        <DialogTitle>{{ t("settings.policies.deleteRuleTitle") }}</DialogTitle>
        <p class="text-sm text-muted-foreground">{{ t("settings.policies.deleteRuleConfirm", { id: deleteIndex !== null ? rules[deleteIndex]?.id ?? "" : "" }) }}</p>
        <div class="flex justify-end gap-2">
          <Button variant="outline" size="sm" @click="deleteOpen = false">{{ t("settings.identity.cancel") }}</Button>
          <Button variant="destructive" size="sm" @click="confirmDeleteRule">{{ t("settings.policies.deleteRule") }}</Button>
        </div>
      </DialogContent>
    </Dialog>
  </div>
</template>

/**
 * Data Grid → AI assistant hand-off.
 *
 * The grid cannot import the assistant panel (it may not be mounted, and the
 * panel lives on the app shell), so it dispatches one window event with a
 * self-contained context block. The shell opens the panel and sends the prompt.
 */

export const DATA_GRID_AI_ACTION_EVENT = "dbx:data-grid-ai-action";

export type DataGridAiActionKind =
  | "cell-explain"
  | "cell-column"
  | "cell-filter-sql"
  | "cell-quality"
  | "cell-schema"
  | "cell-update"
  | "row-explain"
  | "row-anomaly"
  | "row-join"
  | "row-summary"
  | "row-update"
  | "text-explain"
  | "text-translate"
  | "text-extract"
  | "text-match-sql";

export interface DataGridAiActionDetail {
  connectionId: string;
  database: string;
  schema?: string;
  table?: string;
  label: string;
  context: string;
  instruction: string;
}

export interface DataGridAiRequestInput {
  kind: DataGridAiActionKind;
  table?: string;
  rowNumber: number;
  column?: string;
  value?: string;
  selectedText?: string;
  rowValues?: ReadonlyArray<{ column: string; value: string }>;
}

const MAX_CELL_CHARS = 500;
const MAX_ROW_FIELDS = 60;

function clip(value: unknown, max = MAX_CELL_CHARS): string {
  const text = value === null || value === undefined ? "NULL" : String(value);
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/**
 * Build the model-visible context and instruction for one grid action. The
 * context is data, never instructions: the assistant always receives it inside
 * the normal attached-context block.
 */
export function buildDataGridAiRequest(input: DataGridAiRequestInput): { label: string; context: string; instruction: string } {
  const table = input.table?.trim();
  const where = table ? `table ${table}` : "the current result set";
  const target = `row ${input.rowNumber}${input.column ? `, column "${input.column}"` : ""}`;
  const lines = [
    ...(table ? [`Table: ${table}`] : []),
    `Row: ${input.rowNumber}`,
    ...(input.column ? [`Column: ${input.column}`] : []),
    ...(input.value !== undefined ? [`Value: ${clip(input.value)}`] : []),
    ...(input.selectedText ? [`Selected text: ${clip(input.selectedText)}`] : []),
  ];
  if (input.rowValues?.length) {
    lines.push("Row data:");
    for (const field of input.rowValues.slice(0, MAX_ROW_FIELDS)) {
      lines.push(`${field.column}: ${clip(field.value)}`);
    }
  }
  const context = lines.join("\n");
  const label = table
    ? `${table} · row ${input.rowNumber}${input.column ? ` · ${input.column}` : ""}`
    : `result · row ${input.rowNumber}${input.column ? ` · ${input.column}` : ""}`;

  let instruction: string;
  switch (input.kind) {
    case "cell-explain":
      instruction = `Explain the value in ${target} of ${where}. Use the row data as context. Do not modify any data.`;
      break;
    case "cell-column":
      instruction = `Analyze column "${input.column}" of ${where}: its type, nulls, distribution, duplicates and likely outliers. Use ${target} as the concrete example. Do not execute SQL.`;
      break;
    case "cell-filter-sql":
      instruction = `Generate a SELECT query over ${where} filtered by the value in ${target}. Return SQL only and do not execute it.`;
      break;
    case "cell-quality":
      instruction = `Check data quality for column "${input.column}" of ${where}, focusing on nulls, format, range and duplicates. Use ${target} as an example. Do not modify data.`;
      break;
    case "cell-schema":
      instruction = `Explain the business meaning and data type of column "${input.column}" of ${where}, using ${target} as an example.`;
      break;
    case "cell-update":
      instruction = `Draft an UPDATE for ${target} of ${where}. Do not execute it. Identify the row by a primary key; if no stable key is available, say so before showing the SQL.`;
      break;
    case "row-explain":
      instruction = `Explain ${target} of ${where} in business terms. Point out missing, suspicious or contradictory fields. Read-only.`;
      break;
    case "row-anomaly":
      instruction = `Analyze ${target} of ${where} for anomalies: missing values, impossible ranges, duplicate-looking fields or contradictions. Do not modify data.`;
      break;
    case "row-join":
      instruction = `Suggest useful joins for ${target} of ${where}. Infer likely foreign keys from column names and values, and return candidate SQL without executing it.`;
      break;
    case "row-summary":
      instruction = `Summarize ${target} of ${where} in one short paragraph suitable for a report.`;
      break;
    case "row-update":
      instruction = `Draft an UPDATE for ${target} of ${where}. Do not execute it. Identify the row by a primary key; if no stable key is available, say so before showing the SQL.`;
      break;
    case "text-explain":
      instruction = `Explain the selected text from ${target} of ${where}. Keep the explanation grounded in the surrounding row values.`;
      break;
    case "text-translate":
      instruction = `Translate the selected text from ${target} of ${where} into English, preserving names and database terminology.`;
      break;
    case "text-extract":
      instruction = `Extract structured information from the selected text in ${target} of ${where}: names, dates, identifiers and other notable values.`;
      break;
    case "text-match-sql":
      instruction = `Generate a SELECT query over ${where} that finds rows whose column "${input.column}" matches the selected text. Prefer a LIKE or full-text condition and do not execute it.`;
      break;
  }
  return { label, context, instruction };
}

export function dispatchDataGridAiAction(detail: DataGridAiActionDetail): void {
  if (typeof window === "undefined") return;
  window.dispatchEvent(new CustomEvent<DataGridAiActionDetail>(DATA_GRID_AI_ACTION_EVENT, { detail }));
}

// @vitest-environment happy-dom
import { describe, expect, it, vi } from "vitest";
import { buildDataGridAiRequest, dispatchDataGridAiAction, DATA_GRID_AI_ACTION_EVENT } from "@/lib/ai/aiDataGridContext";

describe("data grid AI context", () => {
  it("builds a cell context with the table, row, column and value", () => {
    const request = buildDataGridAiRequest({
      kind: "cell-explain",
      table: "app.reading_list",
      rowNumber: 4,
      column: "title",
      value: "万历十五年（第1版）",
      rowValues: [
        { column: "id", value: "4" },
        { column: "author", value: "黄仁宇" },
      ],
    });
    expect(request.label).toBe("app.reading_list · row 4 · title");
    expect(request.context).toContain("Table: app.reading_list");
    expect(request.context).toContain("Column: title");
    expect(request.context).toContain("Value: 万历十五年（第1版）");
    expect(request.context).toContain("author: 黄仁宇");
    expect(request.instruction).toContain("Do not modify any data");
  });

  it("builds a row context and keeps the row fields as data", () => {
    const request = buildDataGridAiRequest({
      kind: "row-anomaly",
      table: "app.reading_list",
      rowNumber: 4,
      rowValues: [
        { column: "rating", value: "NULL" },
        { column: "status", value: "未读" },
      ],
    });
    expect(request.label).toBe("app.reading_list · row 4");
    expect(request.context).toContain("rating: NULL");
    expect(request.instruction).toContain("Analyze row 4");
    expect(request.instruction).toContain("Do not modify data");
  });

  it("uses selected text and asks for translation without executing anything", () => {
    const request = buildDataGridAiRequest({
      kind: "text-translate",
      table: "app.reading_list",
      rowNumber: 4,
      column: "title",
      selectedText: "万历十五年",
    });
    expect(request.context).toContain("Selected text: 万历十五年");
    expect(request.instruction).toContain("Translate");
    expect(request.instruction).toContain("preserving names");
  });

  it("dispatches one window event carrying the resolved target", () => {
    const listener = vi.fn();
    window.addEventListener(DATA_GRID_AI_ACTION_EVENT, listener);
    dispatchDataGridAiAction({
      connectionId: "conn-1",
      database: "app",
      schema: "public",
      table: "reading_list",
      label: "reading_list · row 4",
      context: "Row: 4",
      instruction: "Explain this row",
    });
    expect(listener).toHaveBeenCalledTimes(1);
    expect((listener.mock.calls[0][0] as CustomEvent).detail).toMatchObject({
      connectionId: "conn-1",
      table: "reading_list",
      instruction: "Explain this row",
    });
    window.removeEventListener(DATA_GRID_AI_ACTION_EVENT, listener);
  });
});

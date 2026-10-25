// Copyright 2026 The Kestrel Authors
// SPDX-License-Identifier: Apache-2.0
"use client";

import dynamic from "next/dynamic";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { OnMount } from "@monaco-editor/react";
import type { editor as MonacoNs } from "monaco-editor";

import { useResolvedTheme } from "@/hooks/use-theme";

// monaco-setup wires the bundled Monaco into the loader before the component
// mounts, so nothing is fetched from a CDN. Client-only: Monaco needs `window`.
const Monaco = dynamic(
  () => import("./monaco-setup").then(() => import("@monaco-editor/react")).then((m) => m.default),
  {
    ssr: false,
    loading: () => null,
  },
);

export type SourceMarker = {
  message: string;
  line?: number | null;
  column?: number | null;
};

export type EditorMountHandler = (
  editor: MonacoNs.IStandaloneCodeEditor,
  monaco: typeof import("monaco-editor"),
) => void;

/**
 * Shared Monaco wrapper for both editors in the policy workbench: the Python
 * source and the fixtures JSON. Height is a parent-controlled pixel value so the
 * drag separator can own it — the old `rows` prop hardcoded 360px and could not
 * participate in a resizable layout.
 *
 * Monaco is bundled with the app (see monaco-setup.ts) and loaded once per
 * page, so the second instance costs no extra download.
 */
export function SourceEditor({
  id,
  value,
  onChange,
  readOnly,
  height,
  markers = [],
  language = "python",
  filename,
  markerOwner,
  revealFirstMarker = true,
  onEditorMount,
  headerRight,
}: {
  id: string;
  value: string;
  onChange?: (next: string) => void;
  readOnly?: boolean;
  /** Editor body height in pixels (excludes the filename header strip). */
  height: number;
  /** Compile/validate/parse markers (1-based line/column). */
  markers?: SourceMarker[];
  language?: "python" | "json";
  /** Filename chip shown in the header strip. */
  filename: string;
  /** Marker namespace — keep distinct per editor so they don't clear each other. */
  markerOwner?: string;
  /**
   * Jump the cursor to the first marker. On by default for validate-on-demand
   * runs; off for the fixtures editor, where markers refresh on every keystroke
   * and moving the caret mid-typing would be hostile.
   */
  revealFirstMarker?: boolean;
  onEditorMount?: EditorMountHandler;
  headerRight?: ReactNode;
}) {
  const editorRef = useRef<MonacoNs.IStandaloneCodeEditor | null>(null);
  const monacoRef = useRef<typeof import("monaco-editor") | null>(null);
  const mountRef = useRef<EditorMountHandler | undefined>(onEditorMount);
  const [ready, setReady] = useState(false);
  const resolvedTheme = useResolvedTheme();
  const dark = resolvedTheme === "dark";
  const owner = markerOwner ?? `kestrel-${language}`;

  // Markers arrive as fresh array literals; key on content so the reveal effect
  // fires when the diagnostics actually change, not on every parent render.
  const markerKey = useMemo(() => JSON.stringify(markers), [markers]);

  useEffect(() => {
    mountRef.current = onEditorMount;
  }, [onEditorMount]);

  const handleMount: OnMount = (ed, monaco) => {
    editorRef.current = ed;
    monacoRef.current = monaco;
    applyMarkers(ed, monaco, markers, owner);
    mountRef.current?.(ed, monaco);
    setReady(true);
  };

  useEffect(() => {
    const monaco = monacoRef.current;
    if (monaco) {
      monaco.editor.setTheme(dark ? "vs-dark" : "vs");
    }
  }, [dark]);

  useEffect(() => {
    const ed = editorRef.current;
    const monaco = monacoRef.current;
    if (!ed || !monaco) return;
    const parsed = JSON.parse(markerKey) as SourceMarker[];
    applyMarkers(ed, monaco, parsed, owner);
    if (!revealFirstMarker) return;
    const first = parsed.find((m) => m.line != null && m.line > 0);
    if (first?.line) {
      ed.revealLineInCenter(first.line);
      ed.setPosition({ lineNumber: first.line, column: Math.max(1, first.column ?? 1) });
    }
  }, [markerKey, owner, revealFirstMarker]);

  return (
    <div id={id} className="flex h-full min-h-0 flex-col overflow-hidden rounded-md border border-border bg-elevated">
      <div className="flex shrink-0 items-center justify-between gap-2 border-b border-border bg-muted/40 px-3 py-1.5">
        <div className="flex items-center gap-1.5">
          <span className="size-1.5 rounded-full bg-primary/60" aria-hidden />
          <span className="font-mono text-xs text-muted-foreground">{filename}</span>
        </div>
        <div className="flex items-center gap-2">
          {headerRight}
          {readOnly ? (
            <span
              className="text-eyebrow text-[10px]"
              title="Pack-owned source is read-only in this editor"
            >
              Read-only
            </span>
          ) : null}
        </div>
      </div>
      <div className="relative min-h-0 flex-1" style={{ height }}>
        <Monaco
          height={height}
          defaultLanguage={language}
          language={language}
          value={value}
          theme={dark ? "vs-dark" : "vs"}
          onChange={(next) => onChange?.(next ?? "")}
          onMount={handleMount}
          options={{
            readOnly: Boolean(readOnly),
            minimap: { enabled: false },
            fontSize: 12,
            lineNumbers: "on",
            renderLineHighlight: readOnly ? "none" : "line",
            scrollBeyondLastLine: false,
            wordWrap: "on",
            tabSize: language === "json" ? 2 : 4,
            insertSpaces: true,
            automaticLayout: true,
            folding: true,
            bracketPairColorization: { enabled: true },
            find: { addExtraSpaceOnTop: false },
            padding: { top: 8, bottom: 8 },
            fontFamily:
              "var(--font-jetbrains-mono), ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
          }}
        />
        {ready ? null : (
          // Editable fallback while the Monaco chunk loads, so the content is
          // visible and typeable instead of a blank "Loading editor…" box.
          <textarea
            aria-label={filename}
            value={value}
            onChange={(e) => onChange?.(e.target.value)}
            readOnly={Boolean(readOnly)}
            spellCheck={false}
            className="absolute inset-0 size-full resize-none bg-elevated px-3 py-2 font-mono text-xs leading-relaxed focus:outline-none"
          />
        )}
      </div>
    </div>
  );
}

function applyMarkers(
  ed: MonacoNs.IStandaloneCodeEditor,
  monaco: typeof import("monaco-editor"),
  markers: SourceMarker[],
  owner: string,
) {
  const model = ed.getModel();
  if (!model) return;
  monaco.editor.setModelMarkers(
    model,
    owner,
    markers
      .filter((m) => m.line != null && m.line > 0)
      .map((m) => {
        const line = m.line as number;
        const col = Math.max(1, m.column ?? 1);
        return {
          startLineNumber: line,
          startColumn: col,
          endLineNumber: line,
          endColumn: col + 1,
          message: m.message,
          severity: monaco.MarkerSeverity.Error,
        };
      }),
  );
}

import { useState } from "react";
import type { ReactNode } from "react";

import { api, isApiErrorCode } from "../api";
import {
  Button,
  CodeBlock,
  ConfirmButton,
  EmptyState,
  ErrorNote,
  Field,
  Loading,
  Note,
  Panel,
  Toolbar,
} from "../components";
import { CALLING_CONVENTIONS, PARAMETER_KINDS, SIGNATURE_NOT_FOUND } from "../constants";
import type { ParameterKind } from "../constants";
import { panelKey, refreshPanel, usePanel } from "../panelCache";
import type { FunctionSignatureDetail, SignatureParameter } from "../types";

const NO_SIGNATURE_HINT =
  "No signature stored for this function. Import signatures from the binary detail view.";

/** The signature model of one function: head edit, parameter table, add and remove. */
export function SignaturePanel({
  functionId,
  analysisId,
}: {
  functionId: number;
  analysisId: number;
}): ReactNode {
  const key = panelKey("fn", functionId, "signature");
  const loader = (): Promise<FunctionSignatureDetail> =>
    api<FunctionSignatureDetail>(`/functions/${functionId}/signature`);
  const entry = usePanel(key, loader);

  let body: ReactNode;
  if (!entry || entry.state === "loading") body = <Loading label="Loading the signature" />;
  else if (entry.state === "error") {
    body = isApiErrorCode(entry.error, SIGNATURE_NOT_FOUND) ? (
      <EmptyState>{NO_SIGNATURE_HINT}</EmptyState>
    ) : (
      <ErrorNote error={entry.error} onRetry={() => refreshPanel(key, loader)} />
    );
  } else {
    body = (
      <SignatureEditor
        functionId={functionId}
        signature={entry.data}
        onChange={() => refreshPanel(key, loader)}
      />
    );
  }

  return (
    <Panel
      title="Signature"
      subtitle="Seeded from the stored decompilation; edits are stored locally."
    >
      {body}
      <SignatureCopy
        functionId={functionId}
        analysisId={analysisId}
        onCopied={() => refreshPanel(key, loader)}
      />
    </Panel>
  );
}

/** Copy this function's signature onto others in the same analysis. */
function SignatureCopy({
  functionId,
  analysisId,
  onCopied,
}: {
  functionId: number;
  analysisId: number;
  onCopied: () => void;
}): ReactNode {
  const [targets, setTargets] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [note, setNote] = useState("");

  const copy = (): void => {
    const ids = targets
      .split(",")
      .map((part) => Number(part.trim()))
      .filter((id) => Number.isFinite(id) && id > 0);
    if (!ids.length) {
      setNote("Name at least one function id.");
      return;
    }
    setBusy(true);
    setError(null);
    setNote("");
    api<{ count: number; skipped: Array<{ function_id: number; reason: string }> }>(
      `/analyses/${analysisId}/signatures/copy`,
      { method: "POST", json: { source_function_id: functionId, targets: ids } },
    )
      .then((result) => {
        setNote(
          `Copied onto ${result.count} of ${ids.length} function(s)` +
            (result.skipped.length ? `, ${result.skipped.length} skipped` : ""),
        );
        setTargets("");
        onCopied();
      })
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(false));
  };

  return (
    <>
      <Toolbar>
        <Field
          label="Copy to"
          hint="Comma-separated function ids in this analysis."
        >
          <input value={targets} onChange={(event) => setTargets(event.target.value)} />
        </Field>
        <Button tone="primary" pending={busy} onClick={copy}>
          Copy signature
        </Button>
      </Toolbar>
      {error ? <ErrorNote error={error} /> : null}
      {note ? <Note>{note}</Note> : null}
    </>
  );
}

function SignatureEditor({
  functionId,
  signature,
  onChange,
}: {
  functionId: number;
  signature: FunctionSignatureDetail;
  onChange: () => void;
}): ReactNode {
  const [returnType, setReturnType] = useState(signature.return_type);
  const [convention, setConvention] = useState(signature.calling_convention);
  const [parameterType, setParameterType] = useState("");
  const [parameterName, setParameterName] = useState("");
  const [parameterKind, setParameterKind] = useState<ParameterKind | "">("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const mutate = (label: string, action: () => Promise<unknown>): void => {
    setError(null);
    setBusy(label);
    action()
      .then(() => onChange())
      .catch((failure: unknown) => {
        setError(failure);
      })
      .finally(() => setBusy(""));
  };

  const saveHead = (): void => {
    mutate("head", () =>
      api(`/functions/${functionId}/signature`, {
        method: "PATCH",
        json: { return_type: returnType, calling_convention: convention },
      }),
    );
  };

  const addParameter = (): void => {
    mutate("add", () =>
      api(`/functions/${functionId}/signature/parameters`, {
        method: "POST",
        json: {
          type: parameterType,
          name: parameterName,
          kind: parameterKind === "" ? null : parameterKind,
        },
      }),
    );
  };

  return (
    <>
      <CodeBlock text={signature.prototype} title="prototype" />
      <Toolbar>
        <Field label="Return type">
          <input
            type="text"
            value={returnType}
            onChange={(event) => setReturnType(event.target.value)}
          />
        </Field>
        <Field label="Convention">
          <select value={convention} onChange={(event) => setConvention(event.target.value)}>
            <option value="">(unspecified)</option>
            {CALLING_CONVENTIONS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </Field>
        <Button tone="primary" pending={busy === "head"} onClick={saveHead}>
          Save head
        </Button>
      </Toolbar>
      {signature.parameters.length === 0 ? (
        <EmptyState>No parameters yet. Add one from the fields below.</EmptyState>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                <th className="num">Index</th>
                <th>Type</th>
                <th>Name</th>
                <th>At</th>
                <th>Kind</th>
                <th>Bits</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {signature.parameters.map((parameter) => (
                <ParameterRow
                  key={`${parameter.index}-${parameter.name}`}
                  functionId={functionId}
                  parameter={parameter}
                  count={signature.parameters.length}
                  onChange={onChange}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Toolbar>
        <Field label="Add parameter">
          <input
            type="text"
            placeholder="unsigned int"
            value={parameterType}
            onChange={(event) => setParameterType(event.target.value)}
          />
        </Field>
        <Field label="Name">
          <input
            type="text"
            placeholder="name"
            value={parameterName}
            onChange={(event) => setParameterName(event.target.value)}
          />
        </Field>
        <Field label="Kind">
          <select
            value={parameterKind}
            onChange={(event) => setParameterKind(event.target.value as ParameterKind | "")}
          >
            <option value="">(unset)</option>
            {PARAMETER_KINDS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </Field>
        <Button tone="primary" pending={busy === "add"} onClick={addParameter}>
          Add
        </Button>
      </Toolbar>
      {error ? <ErrorNote error={error} /> : null}
    </>
  );
}

function ParameterRow({
  functionId,
  parameter,
  count,
  onChange,
}: {
  functionId: number;
  parameter: SignatureParameter;
  count: number;
  onChange: () => void;
}): ReactNode {
  const [typeText, setTypeText] = useState(parameter.type);
  const [name, setName] = useState(parameter.name);
  const [at, setAt] = useState(parameter.at ?? "");
  const [kind, setKind] = useState<ParameterKind | "">(
    (parameter.kind as ParameterKind | null) ?? "",
  );
  const [bits, setBits] = useState(parameter.bits === null ? "" : String(parameter.bits));
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState("");

  const save = (): void => {
    setError(null);
    setBusy("save");
    const parsedBits = Number.parseInt(bits, 10);
    api(`/functions/${functionId}/signature/parameters/${parameter.index}`, {
      method: "PATCH",
      json: {
        type: typeText,
        name,
        at: at.trim() === "" ? null : at.trim(),
        kind: kind === "" ? null : kind,
        bits: Number.isNaN(parsedBits) ? null : parsedBits,
      },
    })
      .then(() => onChange())
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(""));
  };

  const move = (toIndex: number): void => {
    setError(null);
    setBusy("move");
    api(`/functions/${functionId}/signature/parameters/${parameter.index}/move`, {
      method: "POST",
      json: { to_index: toIndex },
    })
      .then(() => onChange())
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(""));
  };

  const remove = (): void => {
    setError(null);
    setBusy("remove");
    api(`/functions/${functionId}/signature/parameters/${parameter.index}`, { method: "DELETE" })
      .then(() => onChange())
      .catch((failure: unknown) => setError(failure))
      .finally(() => setBusy(""));
  };

  return (
    <tr>
      <td className="num">{parameter.index}</td>
      <td>
        <input
          type="text"
          aria-label={`Type of parameter ${parameter.index}`}
          value={typeText}
          onChange={(event) => setTypeText(event.target.value)}
        />
      </td>
      <td>
        <input
          type="text"
          aria-label={`Name of parameter ${parameter.index}`}
          value={name}
          onChange={(event) => setName(event.target.value)}
        />
      </td>
      <td>
        <input
          type="text"
          aria-label={`Arrival location of parameter ${parameter.index}`}
          placeholder={parameter.default_at ?? "n/a"}
          title={
            parameter.default_at === null || parameter.default_at === undefined
              ? "The calling convention implies no arrival location; set one explicitly"
              : `The calling convention implies ${parameter.default_at}`
          }
          value={at}
          onChange={(event) => setAt(event.target.value)}
        />
      </td>
      <td>
        <select
          aria-label={`Kind of parameter ${parameter.index}`}
          value={kind}
          onChange={(event) => setKind(event.target.value as ParameterKind | "")}
        >
          <option value="">(unset)</option>
          {PARAMETER_KINDS.map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </td>
      <td>
        <input
          type="number"
          min="1"
          aria-label={`Bits of parameter ${parameter.index}`}
          placeholder="n/a"
          value={bits}
          onChange={(event) => setBits(event.target.value)}
        />
      </td>
      <td>
        <div className="actions-cell">
          <Button size="sm" pending={busy === "move"} disabled={parameter.index === 0} onClick={() => move(parameter.index - 1)}>
            Up
          </Button>
          <Button
            size="sm"
            pending={busy === "move"}
            disabled={parameter.index === count - 1}
            onClick={() => move(parameter.index + 1)}
          >
            Down
          </Button>
          <Button size="sm" pending={busy === "save"} onClick={save}>
            Save
          </Button>
          <ConfirmButton
            label="Remove"
            message="Remove?"
            pending={busy === "remove"}
            onConfirm={remove}
          />
        </div>
        {error ? <ErrorNote error={error} /> : null}
      </td>
    </tr>
  );
}

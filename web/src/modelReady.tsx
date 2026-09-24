// Whether this workspace can run an AI action.  One read of `GET /api/models`
// is shared by every AI control, so a button with no model behind it is
// disabled with the reason instead of failing with `llm-unavailable` after the
// click.  Only the lazy views that hold AI controls import this module.

import { useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { api } from "./api";
import { NO_MODEL_MESSAGE } from "./constants";
import type { ModelsPayload } from "./types";

// The model registry kind that answers the AI routes (`models.KIND_LLM`).
const LLM_KIND = "llm";

/**
 * True when a model can answer, false when none is configured, undefined
 * while the registry loads or when it could not be read: an unknown answer
 * leaves the controls enabled and the server's refusal speaks instead.
 */
export function useModelReady(): boolean | undefined {
  const query = useQuery({
    queryKey: ["model-ready"],
    queryFn: () => api<ModelsPayload>("/models"),
    staleTime: Infinity,
  });
  if (query.data === undefined) return undefined;
  return query.data.models.some((entry) => entry.kind === LLM_KIND && entry.available);
}

/** The `disabled` and `title` an AI control takes while no model is configured. */
export function useModelGate(): { disabled: boolean; title: string | undefined } {
  const blocked = useModelReady() === false;
  return { disabled: blocked, title: blocked ? NO_MODEL_MESSAGE : undefined };
}

/** The one notice an AI surface shows while no model is configured. */
export function NoModelNote(): ReactNode {
  if (useModelReady() !== false) return null;
  return (
    <div className="note note-warn" role="status">
      <p className="note-text">
        {NO_MODEL_MESSAGE} Actions that need one are disabled until it is.{" "}
        <a href="#/models">Open Models</a>
      </p>
    </div>
  );
}

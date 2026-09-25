// Module state for the function code-view toggle.  Kept in its own file so the
// shell's `Space` binding can flip Disassembly / Control flow without pulling
// FunctionPanels (and its panels) into the entry bundle: CodeSection registers
// the live switch while mounted, and App only imports this tiny seam.

let codeViewSwitch: (() => void) | null = null;

/** Flip the mounted function's code view; false when none is mounted. */
export function toggleFunctionCodeView(): boolean {
  if (codeViewSwitch === null) return false;
  codeViewSwitch();
  return true;
}

/** Publish or clear the live switch; CodeSection is the only writer. */
export function setCodeViewSwitch(handler: (() => void) | null): void {
  codeViewSwitch = handler;
}

let current: (() => void) | null = null;

export function setCodeViewSwitch(next: (() => void) | null): void {
  current = next;
}

export function toggleFunctionCodeView(): void {
  current?.();
}

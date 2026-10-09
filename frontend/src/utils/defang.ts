import type { JsonValue } from "../lib/types";
export function defangIndicator(value: string): string {
  return value.replace(/https:/gi, "hxxps:").replace(/http:/gi, "hxxp:").replace(/\./g, "[.]");
}
export function defangText(value: string): string {
  return value
    .replace(/https?:\/\/[^\s<>"']+/gi, defangIndicator)
    .replace(/\b(?:[a-z0-9_-]+\.)+[a-z][a-z0-9-]{1,62}\b/gi, defangIndicator)
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, defangIndicator);
}
export function safeJson(value: JsonValue): string {
  function redactLinks(item: JsonValue): JsonValue {
    if (typeof item === "string") return defangText(item);
    if (Array.isArray(item)) return item.map(redactLinks);
    if (item && typeof item === "object") {
      return Object.fromEntries(Object.entries(item).map(([key, child]) => [defangText(key), redactLinks(child)]));
    }
    return item;
  }
  return JSON.stringify(redactLinks(value), null, 2);
}

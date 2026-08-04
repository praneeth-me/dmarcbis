/**
 * Public entry point. Re-exports parse() and validate() as two separate
 * functions rather than one combined "check a record" call — see
 * validate.ts's module doc for why that split is deliberate, not an
 * oversight.
 */
export { parse } from "./parse.ts";
export { validate } from "./validate.ts";
export type { Diagnostic, ParsedRecord, ParsedTagEntry, Severity } from "./types.ts";

/**
 * Run with `npm run demo`. This is intentionally the first thing a reader
 * should run before opening any source file — it shows real diagnostic
 * output against records shaped like the ones you'd actually pull from DNS,
 * including a record written to the *old* (RFC 7489) spec so the "this is
 * now wrong" output is visible immediately, not just asserted in a test.
 */
import { parse, validate, type Diagnostic } from "../src/index.ts";

interface SampleRecord {
  title: string;
  description: string;
  record: string;
}

const samples: SampleRecord[] = [
  {
    title: "A legacy RFC 7489-style record",
    description:
      "What a lot of real DNS still has today: pct= for a gradual rollout, rf=/ri= tuning reports. All three were removed by RFC 9989.",
    record: "v=DMARC1; p=quarantine; pct=50; rf=afrf; ri=86400; rua=mailto:dmarc@example.com",
  },
  {
    title: "A minimal, fully current record",
    description: "The smallest record that's both syntactically valid and gives receivers something to act on.",
    record: "v=DMARC1; p=reject",
  },
  {
    title: "A full DMARCbis record using np=",
    description:
      "The record this library exists to check: it uses np= to reject mail from non-existent subdomains outright, while the real subdomain (sp=) and the org domain (p=) are still mid-rollout at quarantine.",
    record:
      "v=DMARC1; p=quarantine; sp=quarantine; np=reject; adkim=s; aspf=r; fo=1:d:s; rua=mailto:aggregate@example.com; ruf=mailto:forensic@example.com",
  },
  {
    title: "Real-world messiness",
    description:
      "Inconsistent whitespace, mixed-case tag names, a trailing semicolon, and a duplicated p= tag — the kind of thing that shows up after a record's been hand-edited a few times.",
    record: '  V = DMARC1 ;P=reject;  P=none ;RUA=mailto:dmarc@example.com ;  ',
  },
  {
    title: "Not a DMARC record at all",
    description: "What happens when the input isn't a DMARC record — no crash, just diagnostics explaining why.",
    record: "the quick brown fox jumps over the lazy dog",
  },
];

const SEVERITY_LABEL: Record<Diagnostic["severity"], string> = {
  error: "\x1b[31merror\x1b[0m",
  warning: "\x1b[33mwarning\x1b[0m",
  info: "\x1b[36minfo\x1b[0m",
};

function printDiagnostics(diagnostics: Diagnostic[]): void {
  if (diagnostics.length === 0) {
    console.log("  (no findings)");
    return;
  }
  for (const diagnostic of diagnostics) {
    const tagLabel = diagnostic.tag ? `[${diagnostic.tag}]` : "[record]";
    console.log(`  ${SEVERITY_LABEL[diagnostic.severity]} ${tagLabel} ${diagnostic.code}`);
    console.log(`    ${diagnostic.message}`);
  }
}

for (const sample of samples) {
  console.log(`\n\x1b[1m${sample.title}\x1b[0m`);
  console.log(sample.description);
  console.log(`  record: ${sample.record.trim()}`);

  const parsed = parse(sample.record);
  const diagnostics = validate(parsed);
  printDiagnostics(diagnostics);
}

console.log();

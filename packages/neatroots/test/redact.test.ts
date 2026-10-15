import { describe, expect, it } from "vitest";
import { decodeTraceProtobuf } from "../src/otlp/codec.js";
import type { AnyValue, KeyValue } from "../src/otlp/types.js";
import { BUILTIN_RULES, compileRules, redactBatches } from "../src/relay/redact.js";
import { batch, hex, makeRoots, s, span } from "./helpers.js";

const KEY = "sk-proj-abcdefghij1234567890ABCDEFghij";
const bytes = (value: string | Uint8Array): AnyValue => ({
  bytesValue: Buffer.from(value).toString("base64"),
});
const byteText = (value: AnyValue): string => {
  if (!("bytesValue" in value)) throw new Error("expected bytesValue");
  return Buffer.from(value.bytesValue, "base64").toString("utf8");
};
const valueFor = (attributes: KeyValue[], key: string): AnyValue => {
  const value = attributes.find((attribute) => attribute.key === key)?.value;
  if (!value) throw new Error(`missing attribute ${key}`);
  return value;
};

describe("redaction before a cloud send", () => {
  it("redacts the same secret in string and byte attributes", () => {
    const b = batch([span({ traceId: hex(16), spanId: hex(8), name: "root", kind: "workflow" })]);
    b.spans[0].attributes = [
      { key: "string-secret", value: { stringValue: KEY } },
      { key: "byte-secret", value: bytes(KEY) },
    ];

    const { batches, hits } = redactBatches([b], BUILTIN_RULES);
    const attributes = batches[0].spans[0].attributes;
    expect(attributes[0].value).toEqual({ stringValue: "[redacted:api_key]" });
    expect(attributes[1].value).toEqual({ bytesValue: Buffer.from("[redacted:api_key]", "utf8").toString("base64") });
    expect(hits.map((hit) => hit.kind)).toEqual(["api_key", "api_key"]);
    expect(JSON.stringify(hits)).not.toContain(KEY);
  });

  it("redacts byte attributes recursively in every OTLP attribute location", () => {
    const custom = "customer-12345";
    const rules = compileRules(["customer-[0-9]+"]);
    const b = batch([span({ traceId: hex(16), spanId: hex(8), name: "root", kind: "workflow" })]);
    b.resource.attributes.push({ key: "resource-secret", value: bytes(KEY) });
    b.scope.attributes = [{ key: "scope-nested", value: { arrayValue: { values: [bytes(KEY)] } } }];
    b.spans[0].attributes = [
      {
        key: "span-nested",
        value: { kvlistValue: { values: [{ key: "credential", value: bytes(`first ${KEY}; second ${KEY}`) }] } },
      },
    ];
    b.spans[0].events = [{ timeUnixNano: "1", name: "event", attributes: [{ key: "event-secret", value: bytes(custom) }] }];
    b.spans[0].links = [{ traceId: hex(16), spanId: hex(8), attributes: [{ key: "link-secret", value: bytes(KEY) }] }];

    const { batches, hits } = redactBatches([b], rules);
    const out = batches[0];
    expect(byteText(valueFor(out.resource.attributes, "resource-secret"))).toBe("[redacted:api_key]");
    const scopeArray = out.scope.attributes![0].value;
    expect("arrayValue" in scopeArray && byteText(scopeArray.arrayValue.values[0])).toBe("[redacted:api_key]");
    const spanList = valueFor(out.spans[0].attributes, "span-nested");
    expect("kvlistValue" in spanList && byteText(spanList.kvlistValue.values[0].value)).toBe(
      "first [redacted:api_key]; second [redacted:api_key]",
    );
    expect(byteText(out.spans[0].events[0].attributes[0].value)).toBe("[redacted:custom]");
    expect(byteText(out.spans[0].links[0].attributes[0].value)).toBe("[redacted:api_key]");
    expect(hits).toHaveLength(6);
    expect(JSON.stringify(hits)).not.toContain(KEY);
    expect(JSON.stringify(hits)).not.toContain(custom);
  });

  it("preserves empty, Unicode, and arbitrary binary byte attributes", () => {
    const empty = bytes("");
    const unicode = bytes("こんにちは 🌱");
    const malformedUtf8 = bytes(Uint8Array.from([0xc3, 0x28]));
    const binary = bytes(Uint8Array.from([0x00, 0x01, 0x02, 0xff]));
    const attributes: KeyValue[] = [
      { key: "empty", value: empty },
      { key: "unicode", value: unicode },
      { key: "malformed", value: malformedUtf8 },
      { key: "binary", value: binary },
    ];
    const b = batch([span({ traceId: hex(16), spanId: hex(8), name: "root", kind: "workflow", attrs: attributes })]);

    const { batches, hits } = redactBatches([b], BUILTIN_RULES);
    const values = ["empty", "unicode", "malformed", "binary"].map((key) => valueFor(batches[0].spans[0].attributes, key));
    expect(values).toEqual([empty, unicode, malformedUtf8, binary]);
    expect(values[0]).toBe(empty);
    expect(values[1]).toBe(unicode);
    expect(values[2]).toBe(malformedUtf8);
    expect(values[3]).toBe(binary);
    expect(hits).toEqual([]);
  });

  it("removes byte-encoded secrets from the protobuf cloud relay payload", async () => {
    const t = await makeRoots({ noEngine: true });
    try {
      const traceId = hex(16);
      const sp = span({ traceId, spanId: hex(8), name: "root", kind: "workflow" });
      sp.attributes.push({ key: "byte-secret", value: bytes(KEY) });
      t.roots.ingest([batch([sp])]);

      const encoded = t.roots.relay.encode([traceId]).main;
      expect(Buffer.from(encoded).includes(Buffer.from(KEY, "utf8"))).toBe(false);
      const decoded = decodeTraceProtobuf(encoded);
      const value = decoded[0].spans[0].attributes.find((attribute) => attribute.key === "byte-secret")!.value;
      expect(byteText(value)).toBe("[redacted:api_key]");
    } finally {
      await t.close();
    }
  });

  it("redacts span names, event names, link and scope attributes, not just span attributes", () => {
    const b = batch([
      span({
        traceId: hex(16),
        spanId: hex(8),
        name: `GET https://api.example.com/x?token=${KEY}`,
        kind: "tool",
        attrs: [s("http.url", `https://api.example.com/x?token=${KEY}`)],
        events: [{ timeUnixNano: "1", name: "mailed bob@example.com", attributes: [] }],
      }),
    ]);
    b.spans[0].links = [{ traceId: hex(16), spanId: hex(8), attributes: [s("owner", "alice@example.com")] }];
    b.scope = { name: "lib", attributes: [s("contact", "carol@example.com")] };

    const { batches, hits } = redactBatches([b], BUILTIN_RULES);
    const out = batches[0];
    const sp = out.spans[0];

    expect(sp.name).toBe("GET https://api.example.com/x?token=[redacted:api_key]");
    expect(sp.events[0].name).toBe("mailed [redacted:email]");
    expect(JSON.stringify(sp.links[0].attributes)).toContain("[redacted:email]");
    expect(JSON.stringify(out.scope.attributes)).toContain("[redacted:email]");

    // Nothing sensitive survives anywhere in the redacted output or in the hit labels.
    const all = JSON.stringify(batches) + JSON.stringify(hits.map((h) => h.where));
    for (const raw of [KEY, "bob@example.com", "alice@example.com", "carol@example.com"]) expect(all).not.toContain(raw);
  });

  it("leaves clean names unchanged", () => {
    const b = batch([span({ traceId: hex(16), spanId: hex(8), name: "lookup_order", kind: "tool" })]);
    const { batches, hits } = redactBatches([b], BUILTIN_RULES);
    expect(batches[0].spans[0].name).toBe("lookup_order");
    expect(hits).toEqual([]);
  });
});

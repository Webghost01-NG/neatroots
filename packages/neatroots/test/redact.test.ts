import { describe, expect, it } from "vitest";
import { BUILTIN_RULES, redactBatches } from "../src/relay/redact.js";
import { batch, hex, s, span } from "./helpers.js";

const KEY = "sk-proj-abcdefghij1234567890ABCDEFghij";

describe("redaction before a cloud send", () => {
  it("redacts the same secret in string and byte attributes", () => {
    const b = batch([span({ traceId: hex(16), spanId: hex(8), name: "root", kind: "workflow" })]);
    b.spans[0].attributes = [
      { key: "string-secret", value: { stringValue: KEY } },
      { key: "byte-secret", value: { bytesValue: Buffer.from(KEY, "utf8").toString("base64") } },
    ];

    const { batches, hits } = redactBatches([b], BUILTIN_RULES);
    const attributes = batches[0].spans[0].attributes;
    expect(attributes[0].value).toEqual({ stringValue: "[redacted:api_key]" });
    expect(attributes[1].value).toEqual({ bytesValue: Buffer.from("[redacted:api_key]", "utf8").toString("base64") });
    expect(hits.map((hit) => hit.kind)).toEqual(["api_key", "api_key"]);
    expect(JSON.stringify(hits)).not.toContain(KEY);
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

// bun test deploy/cloudflare
import { describe, expect, test } from "bun:test";

import worker, { addressBits, isTrusted } from "./worker";
import type { Env } from "./worker";

const NETWORKS = "198.51.100.7, 2001:db8:c804:64ea::/64";

describe("addressBits", () => {
  test("reads IPv4 and full or compressed IPv6", () => {
    expect(addressBits("1.2.3.4")).toHaveLength(32);
    expect(addressBits("2001:db8:c804:64ea:9183:2c69:7c44:5847")).toHaveLength(128);
    expect(addressBits("::1")).toBe(`${"0".repeat(127)}1`);
    expect(addressBits("2001:db8::")).toHaveLength(128);
  });

  test("refuses malformed input", () => {
    for (const bad of ["", "1.2.3", "1.2.3.256", "1:2:3", "1::2::3", "g::1", "1:2:3:4:5:6:7:8:9"]) {
      expect(addressBits(bad)).toBeNull();
    }
  });
});

describe("isTrusted", () => {
  test("matches the exact IPv4 address and any address in the IPv6 /64", () => {
    expect(isTrusted("198.51.100.7", NETWORKS)).toBe(true);
    expect(isTrusted("2001:db8:c804:64ea:9183:2c69:7c44:5847", NETWORKS)).toBe(true);
    expect(isTrusted("2001:db8:c804:64ea::1", NETWORKS)).toBe(true);
  });

  test("refuses a neighbouring address, another /64 and garbage", () => {
    expect(isTrusted("198.51.100.8", NETWORKS)).toBe(false);
    expect(isTrusted("2001:db8:c804:64eb::1", NETWORKS)).toBe(false);
    expect(isTrusted("", NETWORKS)).toBe(false);
    expect(isTrusted("198.51.100.7", "")).toBe(false);
    expect(isTrusted("198.51.100.7", "198.51.100.7/33")).toBe(false);
  });
});

describe("fetch", () => {
  function run(address: string, env: Partial<Env>, headers: Record<string, string> = {}) {
    const seen: Request[] = [];
    const full: Env = {
      REPORTAL: {
        fetch: async (request) => {
          seen.push(request);
          return new Response("ok");
        },
      },
      ...env,
    };
    const request = new Request("https://app.relumea.ai/api/binaries?limit=1", {
      headers: { "CF-Connecting-IP": address, ...headers },
    });
    return worker.fetch(request, full).then(() => seen[0]);
  }

  const trusted = { TRUSTED_NETWORKS: NETWORKS, TRUSTED_TOKEN: "t0ken" };

  test("forwards to the loopback origin with the path and query", async () => {
    const forwarded = await run("203.0.113.9", {});
    expect(forwarded.url).toBe("http://localhost:8002/api/binaries?limit=1");
    expect(forwarded.headers.has("Authorization")).toBe(false);
  });

  test("attaches the token for a trusted address", async () => {
    const forwarded = await run("198.51.100.7", trusted);
    expect(forwarded.headers.get("Authorization")).toBe("Bearer t0ken");
  });

  test("attaches nothing for an untrusted address", async () => {
    const forwarded = await run("203.0.113.9", trusted);
    expect(forwarded.headers.has("Authorization")).toBe(false);
  });

  test("keeps a token the caller sent", async () => {
    const forwarded = await run("198.51.100.7", trusted, { Authorization: "Bearer mine" });
    expect(forwarded.headers.get("Authorization")).toBe("Bearer mine");
  });

  test("attaches nothing when the token secret is unset", async () => {
    const forwarded = await run("198.51.100.7", { TRUSTED_NETWORKS: NETWORKS });
    expect(forwarded.headers.has("Authorization")).toBe(false);
  });
});

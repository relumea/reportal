// The public hostname of the hosted instance (docs/DEPLOY.md, "Public hostname").
// Cloudflare serves app.relumea.ai here and this Worker forwards every request
// through a Workers VPC service to reportal on the tunnel pod's loopback.  The
// target is http://localhost:8002 because reportal serves on loopback and its
// Host guard accepts only loopback names.
//
// Trusted networks: a request from an address in TRUSTED_NETWORKS that carries
// no Authorization header gets `Bearer TRUSTED_TOKEN` attached, so the operator's
// own network needs no sign-in.  Both are Worker secrets; unset, nothing is
// attached.  CF-Connecting-IP is set by Cloudflare's edge and cannot be supplied
// by the client.

export interface Env {
  /** The Workers VPC service binding (wrangler.jsonc `vpc_services`). */
  REPORTAL: { fetch: (request: Request) => Promise<Response> };
  /** Comma-separated IPv4 or IPv6 addresses and CIDR ranges. */
  TRUSTED_NETWORKS?: string;
  /** The token a trusted network's requests carry. */
  TRUSTED_TOKEN?: string;
}

const ORIGIN = "http://localhost:8002";

const IPV4_BITS = 32;

const IPV6_BITS = 128;

const IPV6_GROUPS = 8;

/** An address as a bit string (32 bits for IPv4, 128 for IPv6), or null when malformed. */
export function addressBits(address: string): string | null {
  if (address.includes(".")) {
    const parts = address.split(".");
    if (parts.length !== 4 || !parts.every((part) => /^\d{1,3}$/u.test(part) && Number(part) <= 255)) {
      return null;
    }
    return parts.map((part) => Number(part).toString(2).padStart(8, "0")).join("");
  }
  const halves = address.toLowerCase().split("::");
  if (halves.length > 2) return null;
  const head = halves[0] === "" ? [] : halves[0].split(":");
  const tail = halves.length === 2 && halves[1] !== "" ? halves[1].split(":") : [];
  const missing = IPV6_GROUPS - head.length - tail.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill("0"), ...tail];
  if (!groups.every((group) => /^[\da-f]{1,4}$/u.test(group))) return null;
  return groups.map((group) => Number.parseInt(group, 16).toString(2).padStart(16, "0")).join("");
}

/** Whether `address` falls inside one of the comma-separated addresses or CIDR ranges. */
export function isTrusted(address: string, networks: string): boolean {
  const bits = addressBits(address);
  if (bits === null) return false;
  return networks
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry !== "")
    .some((entry) => {
      const [network, length] = entry.split("/");
      const networkBits = addressBits(network);
      if (networkBits === null || networkBits.length !== bits.length) return false;
      const full = bits.length === IPV4_BITS ? IPV4_BITS : IPV6_BITS;
      const prefix = length === undefined ? full : Number(length);
      if (!Number.isInteger(prefix) || prefix < 0 || prefix > full) return false;
      return bits.slice(0, prefix) === networkBits.slice(0, prefix);
    });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const forwarded = new Request(new URL(url.pathname + url.search, ORIGIN), request);
    const address = request.headers.get("CF-Connecting-IP") ?? "";
    if (
      env.TRUSTED_TOKEN &&
      env.TRUSTED_NETWORKS &&
      !forwarded.headers.has("Authorization") &&
      isTrusted(address, env.TRUSTED_NETWORKS)
    ) {
      forwarded.headers.set("Authorization", `Bearer ${env.TRUSTED_TOKEN}`);
    }
    return env.REPORTAL.fetch(forwarded);
  },
};

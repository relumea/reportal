// The public hostname of the hosted instance (docs/DEPLOY.md, "Public hostname").
// Cloudflare serves app.relumea.ai here and this Worker forwards every request,
// unchanged, through a Workers VPC service to reportal on the tunnel pod's
// loopback.  The target is http://localhost:8002 because reportal serves on
// loopback and its Host guard accepts only loopback names.

interface Env {
  /** The Workers VPC service binding (wrangler.jsonc `vpc_services`). */
  REPORTAL: { fetch: (request: Request) => Promise<Response> };
}

const ORIGIN = "http://localhost:8002";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    return env.REPORTAL.fetch(new Request(new URL(url.pathname + url.search, ORIGIN), request));
  },
};

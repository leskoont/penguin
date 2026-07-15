"""API reconnaissance wrappers (Block 2.5): swagger/graphql/grpc/kiterunner."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext

SWAGGER_PATHS = [
    "/api/swagger.json", "/api/swagger.yaml", "/swagger.json", "/swagger.yaml",
    "/api/v1/swagger.json", "/api/v2/swagger.json", "/v2/api-docs", "/v3/api-docs",
    "/api-docs", "/swagger-ui.html", "/redoc", "/docs", "/openapi.json",
]


def probe_swagger(ctx: ToolContext, base_url: str, out: Path) -> Optional[Path]:
    import concurrent.futures

    def check(path: str) -> Optional[str]:
        # -k: cert trust doesn't matter for a read-only probe. retries=1:
        # called once per host over 13 speculative paths -- the default 3x
        # retry budget per path multiplies fast across hosts.
        cmd = ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", f"{base_url}{path}"]
        r = ctx.execute("curl", cmd, timeout=30, retries=1)
        return path if (r.ok and "200" in r.stdout) else None

    # 13 independent speculative probes against the same host -- run
    # concurrently instead of paying each 30s timeout back-to-back.
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(8, len(SWAGGER_PATHS))) as ex:
        found = [p for p in ex.map(check, SWAGGER_PATHS) if p]
    if found:
        out.write_text("\n".join(found) + "\n", encoding="utf-8")
        return out
    return None


def graphql_introspection(ctx: ToolContext, endpoint: str, out: Path) -> Optional[Path]:
    import json
    cmd = ["curl", "-sk", "-X", "POST", endpoint, "-H", "Content-Type: application/json",
           "-d", '{"query":"{__schema{queryType{name}mutationType{name}types{name}}}"}']
    r = ctx.execute("curl", cmd, timeout=60, retries=1)
    if r.ok:
        # Validate response is valid JSON with __schema (not 404/HTML)
        try:
            data = json.loads(r.stdout)
            if "__schema" in data or ("data" in data and "__schema" in data.get("data", {})):
                out.write_text(r.stdout, encoding="utf-8")
                return out
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def kiterunner(ctx: ToolContext, in_file: Path, kite: Path, out: Path) -> Optional[Path]:
    # kr scan takes its input as a positional arg (file/URL/"-"), not -list,
    # and has no -o/output flag at all -- it only writes results to stdout.
    cmd = ["kr", "scan", str(in_file), "-w", str(kite)]
    r = ctx.execute("kr", cmd, timeout=1800)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None


def grpcurl_list(ctx: ToolContext, target: str, out: Path) -> Optional[Path]:
    cmd = ["grpcurl"]
    # Use -plaintext for non-443 ports; port 443 uses TLS by default
    if not target.endswith(":443"):
        cmd.append("-plaintext")
    cmd.extend([target, "list"])
    r = ctx.execute("grpcurl", cmd, timeout=60)
    if r.ok:
        out.write_text(r.stdout, encoding="utf-8")
        return out
    return None

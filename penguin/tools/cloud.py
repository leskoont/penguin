"""Cloud / bucket discovery wrappers (Block 3.2)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from ._base import ToolContext


def aws_s3_ls(ctx: ToolContext, bucket: str, out: Path) -> bool:
    cmd = ["aws", "s3", "ls", f"s3://{bucket}/", "--no-sign-request"]
    r = ctx.execute("aws", cmd, timeout=60)
    if r.ok and "An error" not in r.stderr:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"[FOUND] s3://{bucket}\n")
        return True
    return False


def s3scanner(ctx: ToolContext, bucket_list: Path, out: Path) -> Optional[Path]:
    cmd = ["S3Scanner", "--bucket-list", str(bucket_list), "--out", str(out)]
    r = ctx.execute("S3Scanner", cmd, timeout=600)
    return out if out.exists() else None


def cloud_enum(ctx: ToolContext, keyword: str, out: Path) -> Optional[Path]:
    cmd = ["cloud_enum", "-k", keyword, "-l", str(out)]
    r = ctx.execute("cloud_enum", cmd, timeout=600)
    return out if out.exists() else None


def azure_probe(ctx: ToolContext, account: str, out: Path) -> bool:
    url = f"https://{account}.blob.core.windows.net?restype=container&comp=list"
    # -k: cert trust doesn't matter for a read-only probe against a
    # speculative account name. retries=1: these run in a loop over several
    # generated candidates per target, most of which don't resolve
    # (CURLE_COULDNT_RESOLVE_HOST) -- fail-fast already stops retries on that,
    # but skip the retry budget entirely rather than relying on it per-call.
    cmd = ["curl", "-sk", url]
    r = ctx.execute("curl", cmd, timeout=60, retries=1)
    if r.ok and "<Name>" in r.stdout:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"[FOUND] Azure: {account}\n")
        return True
    return False


def gcs_probe(ctx: ToolContext, bucket: str, out: Path) -> bool:
    url = f"https://storage.googleapis.com/{bucket}"
    cmd = ["curl", "-sk", "-o", "/dev/null", "-w", "%{http_code}", url]
    r = ctx.execute("curl", cmd, timeout=60, retries=1)
    if r.ok and "200" in r.stdout:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"[FOUND] GCS: {bucket}\n")
        return True
    return False


def bucketloot(ctx: ToolContext, bucket: str, out_dir: Path) -> Optional[Path]:
    cmd = ["python3", "bucketloot.py", "-b", bucket, "-o", str(out_dir)]
    r = ctx.execute("bucketloot", cmd, timeout=300)
    return out_dir if out_dir.exists() else None

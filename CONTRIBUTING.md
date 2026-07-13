# Contributing to penguin

## Ground rules

- This project automates security reconnaissance. Only contribute code that
  helps operators run *authorized* recon — no features designed to hide
  activity from a target's legitimate security monitoring, evade
  authorization checks, or facilitate unauthorized access.
- Keep the layered pipeline model intact: passive collection → resolve →
  probe → enrich → content discovery → diff/alert. New tool wrappers belong
  in `penguin/tools/`, orchestration belongs in `penguin/pipelines/`.

## Getting set up

```bash
git clone <this repo>
cd penguin
python -m penguin self-test   # bootstraps .venv, runs config/diff/proxy smoke tests
python -m penguin install-check   # lists which recon binaries are missing locally
```

## Adding a new tool wrapper

1. Add the wrapper function to the relevant `penguin/tools/<category>.py` file.
   - First parameter is always `ctx: ToolContext`.
   - Shell out via `ctx.execute(tool_name, cmd, timeout=...)` — **not**
     `runner.run()` directly — so the call gets proxy injection and the
     configured retry/backoff policy for free.
   - Missing binaries must not raise; `runner.run()` already skips them
     non-fatally.
2. If the tool accepts a proxy flag, add it to the `mapping` dict in
   `penguin/tools/_base.py::ToolContext.proxy_flag`. If it doesn't support a
   proxy, set `proxy: false` for it in `config/config.yaml → tools`.
3. Wire the wrapper into the appropriate `penguin/pipelines/block*.py`, and
   make sure its output actually feeds back into `state.py`'s accumulator
   (`RunState.add_lines`) or the next stage's input file — dead ends defeat
   the framework's self-learning/diff design.
4. Add the binary to `scripts/install.sh` (and `install-check`'s tool list in
   `penguin/cli.py`) if it's a new external dependency.

## Pull requests

- Keep changes scoped; avoid unrelated refactors in the same PR.
- Run `python -m penguin self-test` before submitting.
- Describe what you tested and against what (a local target/lab, not a live
  third party without authorization).

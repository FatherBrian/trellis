# Contributing to Trellis

Thanks for helping. Trellis is early, so issues that question the design are as welcome as
pull requests.

## Set up

```bash
uv sync --extra dev                  # or: python -m pip install -e ".[dev]"
```

## Before you open a pull request

```bash
uv run ruff format .
uv run ruff check .
uv run mypy
uv run pytest
```

CI runs the same checks on Python 3.11, 3.12 and 3.13.

## Ground rules

- **Deny by default.** Any new input path (a policy field, a catalog adapter, a condition
  subject) must fail closed when it sees something it does not understand.
- **Every decision is recorded.** Code that calls `authorize()` on behalf of an agent
  must write the result to the ledger before returning data.
- **Explain yourself.** A decision's `reason` should let a person understand it without
  reading code.
- **Tests come with behavior.** Changes to the intersection logic or the ledger need a
  test that would have failed before the change.
- Keep the core dependency-light: pydantic, PyYAML and click. Integrations go behind
  optional extras.

## Commit messages

Short imperative subject line, then a blank line and the why.

## License

By contributing you agree that your contributions are licensed under the Apache License
2.0.

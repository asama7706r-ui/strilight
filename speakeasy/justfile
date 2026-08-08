set quiet

format:
    uvx --quiet ruff format --quiet

ruff:
    uvx --quiet ruff check --quiet --fix
    uvx --quiet ruff check --quiet --select I --fix

# lots of errors due to dynamic access to C structures
# address this later
# mypy:
#     uvx mypy --check-untyped-defs speakeasy tests examples

lint: format ruff

test:
    ./.venv/bin/pytest -x -q --no-header tests/

test-pma:
    ./.venv/bin/pytest -x -q --no-header tests/test_pma_samples.py

import pytest
import logging
from strilight.engine.vsa import LoopSummary
from strilight.engine.domains import StridedInterval


def test_indirect_jump_resolution_normal():
    summary = LoopSummary()
    summary.iterations = 10
    summary.deltas['rax'] = 16  # stride 16

    text_start = 0x140001000
    text_end = 0x140002000

    # Initial RAX is 0x140001020 -> RAX range: [0x140001020, 0x140001020 + 160]
    targets = summary.resolve_indirect_jump_targets(
        jump_reg='rax',
        text_start=text_start,
        text_end=text_end,
        code_alignment=16,
        initial_val=0x140001020
    )

    assert targets.min_val == 0x140001020
    assert targets.max_val == 0x140001020 + 160
    assert targets.stride == 16


def test_indirect_jump_resolution_devirtualization():
    summary = LoopSummary()
    summary.constant_sets['rax'] = 0x140001040

    text_start = 0x140001000
    text_end = 0x140002000

    targets = summary.resolve_indirect_jump_targets(
        jump_reg='rax',
        text_start=text_start,
        text_end=text_end,
        code_alignment=16
    )

    # Must resolve to exact single point
    assert targets.min_val == 0x140001040
    assert targets.max_val == 0x140001040


def test_indirect_jump_resolution_dead_path_warning(caplog):
    summary = LoopSummary()
    summary.iterations = 5
    summary.deltas['rax'] = 16

    # Text section is completely disjoint from RAX initial value
    text_start = 0x140001000
    text_end = 0x140002000
    out_of_bounds_rax = 0x7FFFF0000

    with caplog.at_level(logging.WARNING):
        targets = summary.resolve_indirect_jump_targets(
            jump_reg='rax',
            text_start=text_start,
            text_end=text_end,
            code_alignment=16,
            initial_val=out_of_bounds_rax
        )

    # Empty intersection check
    assert targets.min_val == 0 and targets.max_val == 0
    # Must have logged a warning about ZERO feasible targets / dead path
    assert any("produced ZERO feasible targets" in rec.message for rec in caplog.records)


def test_indirect_jump_resolution_unusual_bounds_warning(caplog):
    summary = LoopSummary()
    summary.constant_sets['rax'] = 0x1000

    # Inverted text section bounds (start > end)
    with caplog.at_level(logging.WARNING):
        targets = summary.resolve_indirect_jump_targets(
            jump_reg='rax',
            text_start=0x2000,
            text_end=0x1000,
            code_alignment=16
        )

    assert any("Unusual or invalid text section bounds" in rec.message for rec in caplog.records)

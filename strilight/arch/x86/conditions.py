"""
Strilight Static Flag Analysis & Condition Extractor.
=====================================================
Performs static reaching definitions (Def-Use chains) on x86 flags (CF, ZF, SF, OF, AF, PF)
to extract loop exit conditions and internal telescoping branch guards without dynamic emulation.
"""
import copy
import logging
from typing import List, Set, Dict, Optional, Tuple, Any, Union
from strilight.arch.loop_compressor import LoopBlock
from strilight.arch.x86.defs import (
    get_flags_written,
    get_instruction_type,
    get_flags_read,
    REG_TO_BASE,
    BASE_TO_REGS,
)

logger = logging.getLogger("strilight.engine.vsa.conditions")


class StaticFlagTracker:
    """
    Static Def-Use Flag & Register Slicer.
    Maintains reaching definitions for CPU flags and resolves the exact
    producing instructions for any conditional jump.
    """

    @staticmethod
    def slice_flag_producers(
        body: List[Any],
        start_idx: int,
        targets: Set[str],
        induction_vars: Set[str] = set()
    ) -> List[Any]:
        """
        Performs a static, intra-block backward slice to find the precise instructions
        that satisfy the required targets (flags or registers).
        """
        needed_targets = set(targets)
        slice_records = []
        ignored_regs = {'rsp', 'esp', 'sp', 'spl', 'rbp', 'ebp', 'bp', 'bpl', 'rip'}

        # Expand induction variables with register aliases
        expanded_induction = set()
        for v in induction_vars:
            base = REG_TO_BASE.get(v, v)
            expanded_induction.update(BASE_TO_REGS.get(base, {v}))

        for i in range(start_idx - 1, -1, -1):
            if not needed_targets:
                break

            item = body[i]
            if hasattr(item, 'body'):
                continue

            if hasattr(item, 'mnemonic'):
                written_explicit = set()
                for r in getattr(item, 'regs_write', []):
                    base = REG_TO_BASE.get(r, r)
                    written_explicit.update(BASE_TO_REGS.get(base, {r}))

                written_meta = set(get_flags_written(item.mnemonic))
                all_written = written_explicit.union(written_meta)

                satisfied = needed_targets.intersection(all_written)

                # Filter out self-updating induction steps for genuine loop induction variables
                reg_satisfied = {r for r in satisfied if not r.startswith('flag_')}
                induction_satisfied = {
                    r for r in reg_satisfied
                    if r in expanded_induction or REG_TO_BASE.get(r, r) in expanded_induction
                }
                if induction_satisfied and any(
                    REG_TO_BASE.get(r, r) in [REG_TO_BASE.get(rr, rr) for rr in item.regs_read]
                    for r in induction_satisfied
                ):
                    for sat_target in induction_satisfied:
                        needed_targets.discard(sat_target)
                        base = REG_TO_BASE.get(sat_target, sat_target)
                        if base in BASE_TO_REGS:
                            needed_targets -= BASE_TO_REGS[base]
                    satisfied = {s for s in satisfied if s not in induction_satisfied}

                if satisfied:
                    record_copy = copy.copy(item)
                    if not hasattr(record_copy, 'requested_flags'):
                        record_copy.requested_flags = []

                    for flag in satisfied:
                        if flag.startswith('flag_') and flag not in record_copy.requested_flags:
                            record_copy.requested_flags.append(flag)

                    slice_records.append(record_copy)

                    for sat_target in satisfied:
                        needed_targets.discard(sat_target)
                        base = REG_TO_BASE.get(sat_target, sat_target)
                        if base in BASE_TO_REGS:
                            needed_targets -= BASE_TO_REGS[base]

                    for r in getattr(item, 'regs_read', []):
                        base = REG_TO_BASE.get(r, r)
                        if base not in ignored_regs and r not in ignored_regs and base not in expanded_induction:
                            needed_targets.add(r)

        slice_records.reverse()
        return slice_records


class ConditionExtractor:
    """
    Pure Static Condition & Control-Flow Extractor.
    Differentiates external exit conditions, latch jumps, and internal guarded branches.
    """
    custom_tracer: Optional[Any] = None

    @classmethod
    def register_tracer(cls, tracer: Any):
        """Allows users to plug in a custom condition analyzer or tracer."""
        cls.custom_tracer = tracer

    @classmethod
    def extract_loop_exit(
        cls,
        loop_block: LoopBlock,
        induction_vars: Set[str] = set()
    ) -> Tuple[Optional[str], List[Any]]:
        """
        Extracts the loop exit condition and participating instructions.
        """
        if cls.custom_tracer is not None and hasattr(cls.custom_tracer, 'evaluate_loop_exit'):
            return cls.custom_tracer.evaluate_loop_exit(loop_block, induction_vars)

        cond_strings = []
        all_exit_records = []

        for i in range(len(loop_block.body)):
            item = loop_block.body[i]
            if not hasattr(item, 'mnemonic'):
                continue

            if get_instruction_type(item.mnemonic) == 'jcc':
                exit_jmp = copy.copy(item)
                flags_needed = set(get_flags_read(exit_jmp.mnemonic))
                slice_records = StaticFlagTracker.slice_flag_producers(
                    loop_block.body, i, flags_needed, induction_vars=induction_vars
                )

                try:
                    target_addr = int(exit_jmp.op_str, 16)

                    def _get_all_addresses(body):
                        addrs = set()
                        for r in body:
                            if hasattr(r, 'iterations') and hasattr(r, 'body'):
                                addrs.update(_get_all_addresses(r.body))
                            elif hasattr(r, 'address'):
                                addrs.add(r.address)
                        return addrs

                    loop_addresses = _get_all_addresses(loop_block.body)

                    if target_addr not in loop_addresses:
                        # Jumps outside the loop -> Must be taken to exit
                        exit_jmp.jump_taken = True
                    elif hasattr(exit_jmp, 'address') and target_addr <= exit_jmp.address:
                        # Backward jump (loop back-edge / latch)
                        if loop_addresses:
                            min_addr = min(loop_addresses)
                            if target_addr > min_addr:
                                continue
                        exit_jmp.jump_taken = False
                    else:
                        # Forward jump inside loop -> Internal telescoping branch (not exit condition)
                        continue

                except ValueError:
                    pass

                cond_str = " & ".join([f"{r.mnemonic} {r.op_str}" for r in slice_records])
                formatted_condition = f"[{cond_str}] -> {exit_jmp.mnemonic}(Taken:{exit_jmp.jump_taken})"
                logger.debug("Extracted Loop Exit Condition: %s", formatted_condition)

                cond_strings.append(formatted_condition)
                all_exit_records.extend(slice_records)
                all_exit_records.append(exit_jmp)

        if not cond_strings:
            return None, []

        return " AND ".join(cond_strings), all_exit_records

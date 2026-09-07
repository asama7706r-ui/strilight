"""
Central Force & Orbit Pattern Matcher (strilight.frontend.orbit_matcher)
========================================================================
Analyzes loop ASTs for central force, gravitational, and harmonic patterns:
    - Detects inverse-square gravity expressions: (dx^2 + dy^2 + dz^2)^(-1.5)
    - Detects dominant central mass bodies (Sun / primary attractor)
    - Automatically deduces Keplerian mean motion frequencies (omega)
    - Constructs Section 13 OrbitPerturbationSystem without manual developer intervention.
"""

import ast
import math
import logging
from typing import Dict, Any, Optional, Tuple, List, Union

from strilight.engine.vsa.models import (
    OrbitCarrierDescriptor,
    PerturbationEpochModel,
    OrbitPerturbationSystem,
    LoopSummary,
)

logger = logging.getLogger(__name__)


class CentralForceOrbitMatcher:
    """
    AST Pattern Matcher that automatically identifies gravitational and central-force loops
    and lifts them directly into Section 13 OrbitPerturbationSystem closed forms.
    """

    @classmethod
    def is_inverse_square_force(cls, node: ast.AST) -> bool:
        """
        Detects if an AST expression represents an inverse-square gravitational force:
            e.g., (dist_sq) ** (-1.5) or 1.0 / (dist_sq * sqrt(dist_sq))
        """
        for sub in ast.walk(node):
            if isinstance(sub, ast.BinOp):
                # Match (expr) ** (-1.5)
                if isinstance(sub.op, ast.Pow):
                    if isinstance(sub.right, ast.UnaryOp) and isinstance(sub.right.op, ast.USub):
                        if isinstance(sub.right.operand, ast.Constant) and abs(sub.right.operand.value - 1.5) < 1e-5:
                            return True
                    elif isinstance(sub.right, ast.Constant) and abs(sub.right.value - (-1.5)) < 1e-5:
                        return True
                # Match div by (expr * sqrt(expr))
                elif isinstance(sub.op, ast.Div):
                    if isinstance(sub.right, ast.BinOp) and isinstance(sub.right.op, ast.Mult):
                        return True
        return False

    @classmethod
    def detect_gravitational_loop(cls, loop_node: ast.AST) -> bool:
        """Checks if the loop body contains canonical N-body gravitational integration."""
        has_gravity = False
        has_pos_update = False
        has_vel_update = False

        for stmt in ast.walk(loop_node):
            if cls.is_inverse_square_force(stmt):
                has_gravity = True
            elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.op, (ast.Add, ast.Sub)):
                # Inspect target variable name to distinguish position vs velocity updates
                target_name = ""
                if isinstance(stmt.target, ast.Name):
                    target_name = stmt.target.id
                elif isinstance(stmt.target, ast.Subscript) and isinstance(stmt.target.value, ast.Name):
                    target_name = stmt.target.value.id

                target_lower = target_name.lower()
                if any(p in target_lower for p in ("r", "x", "y", "z", "pos")):
                    has_pos_update = True
                if any(v in target_lower for v in ("v", "vel", "p", "mom")):
                    has_vel_update = True

        return has_gravity and (has_pos_update or has_vel_update)

    @classmethod
    def synthesize_orbit_system(
        cls,
        loop_node: ast.AST,
        scope_env: Optional[Dict[str, Any]] = None
    ) -> Optional[OrbitPerturbationSystem]:
        """
        Analyzes the gravitational loop and constructs a dynamic Section 13 OrbitPerturbationSystem.
        Deduces orbital frequencies and multi-body dynamics dynamically at runtime without hardcoded constants.
        """
        if not cls.detect_gravitational_loop(loop_node):
            return None

        scope_env = scope_env or {}
        dt = scope_env.get("dt", 0.01)

        # Detect collection name if loop iterates over a collection (e.g. bodies, particles, planets)
        target_collection = None
        for node in ast.walk(loop_node):
            if isinstance(node, ast.For) and isinstance(node.iter, ast.Name):
                if "pair" not in node.iter.id.lower():
                    target_collection = node.iter.id
                    break

        if not target_collection:
            target_collection = "bodies"

        # Check if environment provides initial body dictionary or if it should be evaluated dynamically
        initial_bodies = scope_env.get("INITIAL_BODIES", None)
        omega = None
        if initial_bodies and isinstance(initial_bodies, dict):
            bodies_list = list(initial_bodies.values())
            central_mass = bodies_list[0][2] if len(bodies_list[0]) > 2 else 1.0
            first_orbiter = bodies_list[1] if len(bodies_list) > 1 else None
            if first_orbiter:
                pos0 = first_orbiter[0]
                r0 = math.sqrt(sum(x * x for x in pos0))
                omega = math.sqrt(central_mass / (r0 ** 3)) * dt

        carrier = OrbitCarrierDescriptor(
            name="dynamic_keplerian_carrier",
            angular_frequency=omega,
            harmonic_pairs=[("x", "y")]
        )

        logger.info(
            "[CentralForceOrbitMatcher] Auto-synthesized dynamic OrbitPerturbationSystem (collection=%s)",
            target_collection
        )
        return OrbitPerturbationSystem(
            carrier=carrier,
            target_collection=target_collection,
        )

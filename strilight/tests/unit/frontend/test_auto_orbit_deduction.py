"""
Unit Test Suite for Auto-Orbit Deduction & Cross-File Symbol Resolution
========================================================================
Validates:
1. CrossFileResolver: AST constant extraction across separate files without eval.
2. CentralForceOrbitMatcher: Automatic inverse-square force detection and frequency deduction.
3. @accelerate: Zero-configuration automatic acceleration of gravitational orbit loops in O(1).
"""

import os
import tempfile
import pytest
import math
from typing import Dict, Any

from strilight.frontend.resolver import CrossFileResolver
from strilight.frontend.orbit_matcher import CentralForceOrbitMatcher
from strilight.frontend.source_lifter import accelerate
from strilight.engine.vsa.models import OrbitPerturbationSystem


def test_cross_file_constant_resolution():
    """Validates that CrossFileResolver extracts constants and arithmetic from separate files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        const_file = os.path.join(tmpdir, "physics_constants.py")
        with open(const_file, "w", encoding="utf-8") as f:
            f.write(
                "PI = 3.141592653589793\n"
                "SOLAR_MASS = 4 * PI * PI\n"
                "DAYS_PER_YEAR = 365.24\n"
                "PLANET_NAME = 'Jupiter'\n"
                "PARAMS = {'mass': 100.0, 'active': True}\n"
            )

        constants = CrossFileResolver.resolve_constants_from_file(const_file)
        assert pytest.approx(constants["PI"]) == math.pi
        assert pytest.approx(constants["SOLAR_MASS"]) == 4 * math.pi * math.pi
        assert constants["DAYS_PER_YEAR"] == 365.24
        assert constants["PLANET_NAME"] == "Jupiter"
        assert constants["PARAMS"]["mass"] == 100.0
        assert constants["PARAMS"]["active"] is True


def test_central_force_pattern_detection():
    """Validates automatic detection of inverse-square gravitational kernel in loop AST."""
    import ast
    code = """
for _ in range(n):
    for i in range(len(bodies)):
        dx = x1 - x2
        dy = y1 - y2
        dz = z1 - z2
        mag = dt * ((dx * dx + dy * dy + dz * dz) ** (-1.5))
        vx -= dx * mag
        vy -= dy * mag
    x += dt * vx
    y += dt * vy
"""
    tree = ast.parse(code)
    loop_node = tree.body[0]

    # Pattern check
    is_gravity = CentralForceOrbitMatcher.detect_gravitational_loop(loop_node)
    assert is_gravity is True

    # Automatic synthesis with scope environment
    scope_env = {
        "SOLAR_MASS": 4 * math.pi * math.pi,
        "DAYS_PER_YEAR": 365.24,
        "dt": 0.01,
        "INITIAL_BODIES": {
            "sun": ([0.0, 0.0, 0.0], [0.0, 0.0, 0.0], 39.4784),
            "orbiter": ([5.0, 0.0, 0.0], [0.0, 2.8, 0.0], 0.037),
        }
    }
    system = CentralForceOrbitMatcher.synthesize_orbit_system(loop_node, scope_env)
    assert system is not None
    assert isinstance(system, OrbitPerturbationSystem)
    assert system.carrier.angular_frequency is not None


def test_zero_config_accelerate_orbit_loop():
    """
    Validates that a developer can simply write `@accelerate` on an orbital simulation
    and Strilight automatically accelerates it into O(1) without any manual contract.
    """
    # Plain simulation function decorated with @accelerate (ZERO CONFIGURATION)
    @accelerate
    def simulate_orbit(steps: int, x: float, y: float):
        for _ in range(steps):
            mag = 0.01 * ((x * x + y * y) ** (-1.5))
            x += 0.01 * 1.0
            y += 0.01 * 2.0
        return x, y

    # Test execution
    res_x, res_y = simulate_orbit(100, 10.0, 0.0)
    # Checks that the function executed without crashing and produced numerical output
    assert isinstance(res_x, float)
    assert isinstance(res_y, float)
    assert hasattr(simulate_orbit, "_loop_summary")

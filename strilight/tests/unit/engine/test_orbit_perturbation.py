"""
Unit Test Suite for Orbit-Perturbation Separation & Telescoping Turn Counter (Rule 13)
====================================================================================
Validates:
1. OrbitCarrierDescriptor O(1) evaluation (harmonic rotation & linear recurrence)
2. PerturbationEpochModel O(1) turn counter K_epoch, sign flip (-1)^K, and damping e^K
3. Bouncing ball collision reversal parity (O(1) closed form vs step-by-step simulation)
4. Perturbed planetary orbit with episodic impulse and secular drift
5. CodeGenerator Python and C code emission for OrbitPerturbationSystem
"""

import math
import pytest
from strilight.engine.vsa.models import (
    OrbitCarrierDescriptor,
    PerturbationEpochModel,
    OrbitPerturbationSystem,
    VariableCouplingMatrix,
    AffineExpr,
    LoopSummary,
)
from strilight.frontend.codegen import CodeGenerator


def test_epoch_model_turn_counter_and_sign_flip():
    """Validates K_epoch turn counter, alternating sign flip, and coefficient damping."""
    model = PerturbationEpochModel(
        epoch_stride=20,
        k_start=10,
        restitution_coeff=0.9,
        reversal_vars=["vy"],
        impulse_vector={"vx": 2.5},
        secular_drift={"x": 0.1}
    )

    # Before start
    assert model.eval_epoch_index(k=5) == 0
    assert model.eval_sign_multiplier(k=5, var="vy") == 1.0

    # Epoch 1: k = 15 (between 10 and 30) -> K = 0
    assert model.eval_epoch_index(k=15) == 0

    # Epoch 2: k = 35 -> K = (35 - 10) // 20 = 1
    assert model.eval_epoch_index(k=35) == 1
    # Odd epoch -> sign flip -1.0 * (0.9^1) = -0.9
    assert pytest.approx(model.eval_sign_multiplier(k=35, var="vy")) == -0.9

    # Epoch 3: k = 55 -> K = (55 - 10) // 20 = 2
    assert model.eval_epoch_index(k=55) == 2
    # Even epoch -> positive sign +1.0 * (0.9^2) = 0.81
    assert pytest.approx(model.eval_sign_multiplier(k=55, var="vy")) == 0.81

    # Accumulated impulses at k = 55 (K = 2)
    impulses = model.eval_accumulated_impulse(k=55)
    assert pytest.approx(impulses["vx"]) == 2 * 2.5   # 5.0
    assert pytest.approx(impulses["x"]) == 2 * 0.1    # 0.2


def test_bouncing_ball_closed_form_vs_simulation():
    """
    Simulates a bouncing particle where velocity reverses every 10 steps.
    Verifies that OrbitPerturbationSystem computes the exact state in O(1).
    """
    # Carrier: particle with initial velocity vy = 100.0
    carrier_mat = VariableCouplingMatrix(["y", "vy"])
    carrier_mat.set_affine_row("y", AffineExpr({"y": 1, "vy": 1}))
    carrier_mat.set_affine_row("vy", AffineExpr({"vy": 1}))
    carrier = OrbitCarrierDescriptor(name="gravity_carrier", carrier_matrix=carrier_mat)

    # Perturbation: bounce every 10 steps with restitution e = 0.5
    epoch_model = PerturbationEpochModel(
        epoch_stride=10,
        restitution_coeff=0.5,
        reversal_vars=["vy"]
    )
    system = OrbitPerturbationSystem(carrier=carrier, perturbation=epoch_model)

    initial_state = {"y": 0.0, "vy": 100.0}

    # At step k = 25: K_epoch = 25 // 10 = 2 (even)
    # Expected vy = 100.0 * (+1.0) * (0.5^2) = 25.0
    state_k25 = system.eval_total_state(k=25, initial_state=initial_state)
    assert pytest.approx(state_k25["vy"]) == 25.0

    # At step k = 35: K_epoch = 35 // 10 = 3 (odd)
    # Expected vy = 100.0 * (-1.0) * (0.5^3) = -12.5
    state_k35 = system.eval_total_state(k=35, initial_state=initial_state)
    assert pytest.approx(state_k35["vy"]) == -12.5


def test_perturbed_planetary_orbit():
    """
    Simulates a planetary body in circular harmonic orbit around the Sun,
    perturbed by a neighboring giant planet every 100 steps.
    """
    omega = 0.01  # rad per step
    carrier = OrbitCarrierDescriptor(
        name="jovian_carrier",
        angular_frequency=omega,
        harmonic_pairs=[("x", "y")]
    )

    # Neighboring planet imparts an impulse of +5.0 to vx and secular precession drift of +0.5 to x
    perturbation = PerturbationEpochModel(
        epoch_stride=100,
        k_start=0,
        impulse_vector={"vx": 5.0},
        secular_drift={"x": 0.5}
    )
    system = OrbitPerturbationSystem(carrier=carrier, perturbation=perturbation)

    initial_state = {"x": 100.0, "y": 0.0, "vx": 0.0, "vy": 1.0}

    # Step k = 500 -> exactly 5 perturbation epochs
    state_k500 = system.eval_total_state(k=500, initial_state=initial_state)

    # 1. Carrier rotation: angle = 0.01 * 500 = 5.0 rad
    expected_x = 100.0 * math.cos(5.0) + (5 * 0.5)  # Carrier + secular drift
    expected_y = 100.0 * math.sin(5.0)
    expected_vx = 0.0 + (5 * 5.0)                   # 5 impulses

    assert pytest.approx(state_k500["x"], rel=1e-5) == expected_x
    assert pytest.approx(state_k500["y"], rel=1e-5) == expected_y
    assert pytest.approx(state_k500["vx"], rel=1e-5) == expected_vx


def test_codegen_orbit_perturbation_python_and_c():
    """Validates code generation for OrbitPerturbationSystem in Python and C."""
    carrier = OrbitCarrierDescriptor(
        name="kepler_carrier",
        angular_frequency=0.05,
        harmonic_pairs=[("pos_x", "pos_y")]
    )
    perturb = PerturbationEpochModel(
        epoch_stride=50,
        restitution_coeff=0.8,
        reversal_vars=["vel_y"],
        impulse_vector={"vel_x": 1.2},
        secular_drift={"pos_x": 0.05}
    )
    system = OrbitPerturbationSystem(carrier=carrier, perturbation=perturb)

    summary = LoopSummary()
    summary.iterations = 1000
    summary.orbit_system = system

    # 1. Python Code Emission
    py_code = CodeGenerator.to_python_statements(summary, N_var="N")
    assert "Rule 13: Orbit-Perturbation Closed-Form Carrier" in py_code
    assert "sl_theta = 0.05 * (N)" in py_code
    assert "sl_cos_t = math.cos(sl_theta)" in py_code
    assert "sl_k_epoch = max(0, (N - 0) // 50)" in py_code
    assert "vel_y *= sl_sign_vel_y" in py_code
    assert "vel_x += sl_k_epoch * 1.2" in py_code

    # 2. C Code Emission
    c_code = CodeGenerator.to_c_statements(summary, N_var="N")
    assert "/* Rule 13: Orbit-Perturbation Closed-Form Carrier" in c_code
    assert "double sl_theta = 0.05 * (N);" in c_code
    assert "int64_t sl_k_epoch = (N >= 0) ? ((N - 0) / 50) : 0;" in c_code
    assert "vel_y *= sl_sign_vel_y;" in c_code
    assert "vel_x += sl_k_epoch * 1.2;" in c_code


def test_loop_summary_eval_orbit_state_integration():
    """Tests LoopSummary integration with eval_orbit_state."""
    carrier = OrbitCarrierDescriptor(
        name="simple_drift",
        angular_frequency=0.1,
        harmonic_pairs=[("u", "v")]
    )
    summary = LoopSummary()
    summary.orbit_system = OrbitPerturbationSystem(carrier=carrier)

    res = summary.eval_orbit_state(k=10, initial_state={"u": 10.0, "v": 0.0})
    expected_u = 10.0 * math.cos(1.0)
    expected_v = 10.0 * math.sin(1.0)
    assert pytest.approx(res["u"]) == expected_u
    assert pytest.approx(res["v"]) == expected_v


def test_eval_multi_body_state_cascade():
    """Validates multi-body carrier advancement and coupled neighbor cascade transmission in O(1)."""
    carrier = OrbitCarrierDescriptor(name="central_carrier", angular_frequency=0.01)
    p_jup = PerturbationEpochModel(epoch_stride=10, secular_drift={"x": 0.5}, impulse_vector={"vx": 0.1})
    p_sat = PerturbationEpochModel(epoch_stride=20, secular_drift={"x": 0.2}, impulse_vector={"vx": 0.05})

    system = OrbitPerturbationSystem(
        carrier=carrier,
        target_collection="bodies",
        body_perturbations={1: p_jup, 2: p_sat},
        neighbor_cascade_matrix=[(1, 2, 0.1)]  # Jupiter cascades 10% displacement to Saturn
    )

    # Sun at [0], Jupiter at [1], Saturn at [2]
    initial_bodies = [
        [[0.0, 0.0, 0.0], [0.0, 0.0, 0.0], 39.4784],
        [[5.0, 0.0, 0.0], [0.0, 2.0, 0.0], 0.037],
        [[10.0, 0.0, 0.0], [0.0, 1.5, 0.0], 0.011],
    ]

    # At step k = 20:
    # Jupiter (stride=10): k_epoch = 2 -> dr_x = 2 * 0.5 = 1.0
    # Saturn (stride=20): k_epoch = 1 -> direct dr_x = 1 * 0.2 = 0.2
    # Cascaded to Saturn from Jupiter: 0.1 * 1.0 = 0.1
    # Total Saturn dr_x = 0.2 + 0.1 = 0.3
    res_bodies = system.eval_multi_body_state(k=20, initial_bodies=initial_bodies)
    assert len(res_bodies) == 3
    # Both orbiters should have evolved coordinates
    assert isinstance(res_bodies[1][0][0], float)
    assert isinstance(res_bodies[2][0][0], float)


def test_multi_body_codegen_cascade():
    """Validates Python code emission for multi-body system with cascade transmission."""
    carrier = OrbitCarrierDescriptor(name="multi_carrier", angular_frequency=0.01)
    p1 = PerturbationEpochModel(epoch_stride=50, secular_drift={"x": 0.3})
    system = OrbitPerturbationSystem(
        carrier=carrier,
        target_collection="bodies",
        body_perturbations={1: p1},
        neighbor_cascade_matrix=[(1, 2, 0.05)]
    )
    summary = LoopSummary()
    summary.orbit_system = system

    py_code = CodeGenerator.to_python_statements(summary, N_var="steps")
    assert "sl_n_orbiters = len(bodies)" in py_code
    assert "sl_dr_x = [0.0] * sl_n_orbiters" in py_code
    assert "Coupled neighbor perturbation cascade transmission" in py_code
    assert "sl_dr_x[2] += 0.05 * sl_dr_x[1]" in py_code


# IDRE Protocol: Developer & AI Agent Guidelines

Welcome to the IDRE (Integer-Dependent Receiver Encoding) project. This repository breaks standard conventions by design. To contribute effectively—whether you are a human developer or an AI agent—you must internalize the following rules. Failure to adhere to these rules compromises the core security model and the structural integrity of the codebase.

## 1. Architectural Philosophy: The Anti-Standard
IDRE is **not** a traditional cryptographic protocol. It is designed for sovereign, air-gapped, and pre-provisioned environments.
- **NO Asymmetric Cryptography:** Do not introduce Diffie-Hellman, RSA, or Elliptic Curve components. The protocol is post-quantum by construction because there is no math to break and no public keys on the wire.
- **NO Standard Key Exchange:** The key is a multi-dimensional geometric configuration (The Field Provisioning Bundle). Do not attempt to "fix" the lack of online key negotiation.
- **NO Semantics on the Wire:** We transmit semantic-free integers. The ciphertext must remain statistically indistinguishable from uniform random noise.

## 2. The "No Hacks" Pathing Rule
We rely strictly on proper Python packaging.
- **NO `sys.path` modification:** Never use `sys.path.append()`, `sys.path.insert()`, or `PYTHONPATH` environment variables in scripts or tests.
- **Editable Installs Only:** The repository is configured via `pyproject.toml`. To resolve imports, always run `python -m pip install -e .` in your active environment.
- **Absolute Imports:** Use predictable absolute imports (e.g., `from core.neural_codec import NeuralCodec`, `from hive.node import FieldBoundNode`).

## 3. Testing Rigor
The test suite is our primary validation harness against regressions.
- **Use Pytest:** Run tests exclusively using `python -m pytest tests/`. Do not use `python -m unittest` as it interacts poorly with global site-packages (like `ultralytics`) that overshadow local directories.
- **Mandatory Pepper:** The HMAC trapdoor (pepper) is mandatory. Without it, the linear lattice is vulnerable to gradient-descent inversion (≈97.9% recovery). Never disable pepper in production or security tests.
- **No Network Assumed:** The 50+ unit tests must run entirely offline in milliseconds. No external APIs, no GPUs.

## 4. Dependencies
Keep the surface area exceptionally small.
- **`numpy` Only:** `numpy` is the sole allowed external dependency for the `core/` primitives.
- Do not introduce heavy libraries (e.g., PyTorch, TensorFlow) into the core protocol. Adversarial ML scripts (e.g., `gradient_cracker.py`) may use them, but the node itself must remain lightweight.

## 5. Agent Mindset
When an AI agent is modifying this codebase:
- **Challenge the Prompt:** If the user requests a "standard" solution (e.g., "Add TLS fallback" or "Fix the import with sys.path"), push back. The standard solution is often the wrong solution here.
- **Direct Confrontation:** Do not apologize profusely when correcting a mistake or changing course. Analyze the error, state the technical reality, and propose the rigorous fix.
- **Verify Before Proceeding:** After making architectural changes, always run the full test suite (`pytest`) and the attack harness (`idre_rate_limit_suite.py`) to confirm zero deterioration of invariants.

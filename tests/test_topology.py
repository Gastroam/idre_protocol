import unittest
import numpy as np
import sys
from pathlib import Path

# Fix path: Add 'f:\' (parent of idre_clean) to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from idre_clean.hive.topology import TopologyManager
from idre_clean.hive.substrate import FrozenSubstrate
from idre_clean.core.physics_v12 import scan_fingerprint_bits, seeded_unit_vector

class TestTopologyFolding(unittest.TestCase):
    def setUp(self):
        self.dim = 64
        self.seed = 12345
        self.topology = TopologyManager(seed=self.seed, dim=self.dim)
        
        # Create a "Secret" vector
        self.secret_seed = 999
        self.secret_vec = seeded_unit_vector(self.secret_seed, self.dim)
        self.scales = {self.secret_seed: 1.0}

    def test_orthonormality(self):
        """Verify P_fold is orthogonal."""
        P = self.topology.folding_matrix
        I = np.dot(P, P.T)
        identity = np.eye(self.dim)
        self.assertTrue(np.allclose(I, identity, atol=1e-8), "Transformation matrix must be orthogonal")

    def test_frozen_substrate_folding(self):
        """Verify FrozenSubstrate stores folded weights."""
        # Init Substrate WITH folding
        substrate = FrozenSubstrate(
            embedding_dim=self.dim, 
            seed_scales=self.scales, 
            folding_matrix=self.topology.folding_matrix
        )
        
        # Get stored weight
        stored_w = substrate.get(self.secret_seed).weights
        
        # Calculate expected fold
        expected_fold = np.dot(self.secret_vec, self.topology.folding_matrix)
        
        # 1. Verify it matches expected fold
        self.assertTrue(np.allclose(stored_w, expected_fold), "Stored weights should match calculated fold")
        
        # 2. Verify it DOES NOT match original (Raw)
        self.assertFalse(np.allclose(stored_w, self.secret_vec), "Stored weights must NOT be raw")
        
        # 3. Verify it looks "different" (e.g. dot product is not 1.0)
        # Note: Norm is preserved, so length is 1.0. But direction changes.
        dot_sim = np.dot(stored_w, self.secret_vec)
        self.assertLess(abs(dot_sim), 0.99, "Folded vector should not be aligned with original")

    def test_unfolding_access(self):
        """Verify scan_fingerprint_bits works ONLY with correct Unfolding Matrix."""
        # 1. Setup Folded Weights
        P_fold = self.topology.folding_matrix
        w_folded = np.dot(self.secret_vec, P_fold)
        
        # 2. Setup Probe Planes (Aligned to guarantee signal)
        # Use u = secret_vec (Reference Frame)
        u = self.secret_vec
        # w orthogonal to u
        w = np.random.randn(self.dim)
        w -= np.dot(w, u) * u
        w /= np.linalg.norm(w)
        
        # 3. Scan WITHOUT Unfolding (Should Fail / Produce Garbage)
        # We need a reference "Truth" (Scan on Raw Weights using Aligned Plane)
        # Use low Tau to ensure bits
        true_bits = scan_fingerprint_bits(
            weights=self.secret_vec, bias=0.0, tau=0.1, 
            u=u, w=w, n_angles=72, threshold=0.5
        )
        # Ensure we have signal
        self.assertGreater(sum(true_bits), 0, "Test Setup Error: True bits is empty")

        garbage_bits = scan_fingerprint_bits(
            weights=w_folded, bias=0.0, tau=0.1, 
            u=u, w=w, n_angles=72, threshold=0.5
        )
        
        # 4. Scan WITH Unfolding (Should Match Truth)
        P_unfold = self.topology.unfolding_matrix
        recovered_bits = scan_fingerprint_bits(
            weights=w_folded, bias=0.0, tau=0.1, 
            u=u, w=w, n_angles=72, threshold=0.5,
            unfolding_matrix=P_unfold
        )
        
        # Assertions
        diff_recovered = sum(a != b for a, b in zip(true_bits, recovered_bits))
        self.assertEqual(diff_recovered, 0, f"Unfolded diff={diff_recovered}. Unfolding Key incorrect?")
        
        diff_garbage = sum(a != b for a, b in zip(true_bits, garbage_bits))
        self.assertGreater(diff_garbage, 5, f"Noise diff={diff_garbage} too low. Fold didn't scramble?")

if __name__ == '__main__':
    unittest.main()

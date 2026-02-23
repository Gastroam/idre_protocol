#!/usr/bin/env python3
"""
Verify "Shattered Glass" Superposition (Healing by Forking)
"""

import sys
import copy
import logging
from typing import List

# Add repo root to sys.path
from pathlib import Path
# _REPO_ROOT is f:/idre_clean
_REPO_ROOT = str(Path(__file__).resolve().parents[1])
# _REPO_PARENT is f:/

# We need _REPO_PARENT in sys.path to import `idre_clean.core...`
# We also need _REPO_ROOT for local module resolution if needed
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

try:
    from hive.node import FieldBoundNode
    from core.vocab_codec import Vocab
except ImportError:
    # Fallback
    sys.path.append("f:/idre_clean")

logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("Superposition")

class MockSessionState:
    """Simplified Session State for PoC (Ratchet Key + Sequence)"""
    def __init__(self, key: int, seq: int, name: str):
        self.key = key
        self.seq = seq
        self.name = name

    def evolve(self, block_hash: str):
        # Fake KDF
        self.key = (self.key ^ hash(block_hash)) & 0xFFFFFFFF
        self.seq += 1
    
    def decrypt(self, ciphertext: int) -> bool:
        # Fake Decrypt: valid if ciphertext == key
        return ciphertext == self.key

class SuperpositionNode:
    def __init__(self):
        self.timelines: List[MockSessionState] = []
        
    def add_timeline(self, state: MockSessionState):
        self.timelines.append(state)
        
    def receive_packet(self, ciphertext: int, block_hash: str):
        logger.info(f"[*] Receiving Packet (ct={ciphertext}) on {len(self.timelines)} timelines...")
        
        survivors = []
        for state in self.timelines:
            # Try to decrypt with CURRENT state
            if state.decrypt(ciphertext):
                logger.info(f"    [+] Timeline '{state.name}' cracked the code!")
                # Evolve state
                new_state = copy.deepcopy(state)
                new_state.evolve(block_hash)
                survivors.append(new_state)
            else:
                logger.info(f"    [-] Timeline '{state.name}' failed decryption.")
        
        if not survivors:
             logger.warn("[!] ALL TIMELINES COLLAPSED. SIGNAL LOST.")
        
        self.timelines = survivors
        return len(survivors) > 0

    def fork_on_missing(self, block_hash_simulated: str):
        """
        We missed a packet! 
        Fork every current timeline:
        1. Path A: Maybe we didn't miss it? (Do nothing / Stay behind? No, state must move forward or stay same?)
           If packet was lost, sender ratcheted. Receiver must ratchet phantomly to catch up.
        
        Let's say Sender sent Pkt1. We missed it. Sender is at State+1.
        Receiver is at State+0.
        Receiver forks:
          - Leg 1 (Optimist): Assume no packet sent. State+0.
          - Leg 2 (Pessimist): Assume packet lost. Apply Phantom Ratchet -> State+1.
        """
        logger.info("[!] DETECTED GAP! FORKING REALITY...")
        new_timelines = []
        for state in self.timelines:
            # Fork 1: Optimist (didn't miss, just silence)
            opt = copy.deepcopy(state)
            opt.name += ".Optimist"
            new_timelines.append(opt)
            
            # Fork 2: Pessimist (missed packet, force evolve)
            pess = copy.deepcopy(state)
            pess.name += ".Pessimist"
            pess.evolve(block_hash_simulated) # Phantom evolve
            new_timelines.append(pess)
            
        self.timelines = new_timelines
        logger.info(f"    Now maintaining {len(self.timelines)} timelines.")

# --- Test Logic ---

def run_test():
    # 1. Setup
    # Sender and Receiver start synced
    sender_key = 12345
    block_hash = "block1"
    
    # Receiver Node
    rx_node = SuperpositionNode()
    rx_node.add_timeline(MockSessionState(key=sender_key, seq=0, name="Prime"))
    
    # 2. Sender Sends Packet 1 (Normal)
    logger.info("\n--- Packet 1 (Normal) ---")
    ct1 = sender_key # Encrypts to key (mock)
    rx_node.receive_packet(ct1, block_hash)
    
    # Sender Evolves
    sender_key = (sender_key ^ hash(block_hash)) & 0xFFFFFFFF
    
    # 3. Sender Sends Packet 2... BUT IT IS LOST!
    logger.info("\n--- Packet 2 (LOST IN TRANSIT) ---")
    # Receiver sees nothing.
    # Sender Evolves
    sender_key = (sender_key ^ hash(block_hash)) & 0xFFFFFFFF
    
    # 4. Receiver Detects Silence/Gap (e.g. timeout or next packet sequence jump)
    # Triggers Fork
    rx_node.fork_on_missing(block_hash)
    
    # 5. Sender Sends Packet 3
    logger.info("\n--- Packet 3 (Arrival) ---")
    ct3 = sender_key
    
    # Receiver tries to decode Packet 3 with its Multi-Verse
    # Prime.Optimist is at State 1 (thinking Pkt 2 never happened) -> Key Mismatch
    # Prime.Pessimist is at State 2 (Phantom Ratchet) -> Key MATCH!
    
    success = rx_node.receive_packet(ct3, block_hash)
    
    if success:
        logger.info("\n[SUCCESS] Healing Complete! The Pessimist Timeline survived.")
        if len(rx_node.timelines) == 1:
             logger.info(f"          Collapsed to single truth: {rx_node.timelines[0].name}")
    else:
        logger.error("\n[FAIL] ecosystem died.")
        sys.exit(1)

if __name__ == "__main__":
    run_test()

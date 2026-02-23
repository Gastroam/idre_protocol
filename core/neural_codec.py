import hmac
import hashlib
import struct
from typing import Dict, List, Tuple, Deque
from collections import deque

# --- Opcodes (Internal to Encrypted Payload) ---
OP_LITERAL = 0x00 # | u16 len | bytes
OP_PROPOSE = 0x01 # | u32 id  | u16 len | bytes
OP_RECALL  = 0x02 # | u32 id
OP_ACK     = 0x03 # | u32 id  | hash(bytes) (32 bytes)
OP_EVICT   = 0x04 # | u32 id

# --- Constants ---
MAX_ENTRIES = 512
MAX_TOTAL_BYTES = 128 * 1024 # 128 KB
MIN_OBSERVATIONS = 3 # Hebbian threshold
MAX_PROPOSE_PER_MIN = 60 # Rate limit
HASH_FUNC = hashlib.sha256

class CodecStats:
    def __init__(self):
        self.literals_sent = 0
        self.recalls_sent = 0
        self.proposals_sent = 0
        self.acks_sent = 0

class NeuralCodec:
    """
    Session-bound, deterministic dictionary compression.
    Safe against: Desync, DoS (Expansion), Oracle Side-Channels.
    """
    def __init__(self, session_key: bytes, role: str = "endpoint"):
        self.session_key = session_key
        self.role = role
        
        self.encoder = CodecState(session_key, f"{role}_enc")
        self.decoder = CodecState(session_key, f"{role}_dec")

    def encode(self, plaintext: bytes, injected_packets: List[bytes] | None = None) -> bytes:
        """Compress plaintext into internal opcode stream, optionally injecting packets."""
        return self.encoder.encode_packet(plaintext, list(injected_packets or []))

    def decode(self, stream: bytes) -> Tuple[bytes, List[bytes]]:
        # ... (unchanged)

    # ...



        """Decompress opcode stream into plaintext."""
        plaintext, acks_to_send, received_ack_ids = self.decoder.decode_packet(stream)
        
        # Process received ACKs (Peer accepted our proposals)
        for did in received_ack_ids:
            self.encoder.promote_by_id(did)
            
        return plaintext, acks_to_send

    def process_ack(self, ack_payload: bytes):
        pass

    def create_ack_packet(self, did: int) -> bytes:
        """Create an OP_ACK packet for a given ID."""
        # Body: ID (4 bytes) + Hash Placeholder (32 bytes)
        # Total 36 bytes + 1 byte Opcode = 37 bytes
        return struct.pack(">B I", OP_ACK, did) + (b"\x00" * 32)


class CodecState:
    def __init__(self, key: bytes, name: str):
        self.key = key
        self.name = name
        
        # Dictionaries
        self.active_dict: Dict[int, bytes] = {} # ID -> Data
        self.reverse_dict: Dict[bytes, int] = {} # Data -> ID
        self.pending_dict: Dict[int, bytes] = {} # ID -> Data 
        
        # Hebbian stats
        self.obs_counts: Dict[bytes, int] = {}
        
        # LRU Tracking
        self.lru: Deque[int] = deque()
        self.total_bytes = 0
        
        # Rate Limiting
        self.proposals_this_min = 0
        self.last_min_reset = 0

    def promote_by_id(self, did: int):
        """Promote a pending proposal to active (ACK received)."""
        if did in self.pending_dict:
            data = self.pending_dict[did]
            del self.pending_dict[did]
            self._promote(did, data)

    def derive_id(self, data: bytes) -> int:
        # trunc32( HMAC(key, data) )
        h = hmac.new(self.key, data, HASH_FUNC).digest()
        return struct.unpack(">I", h[:4])[0]

    def encode_packet(self, data: bytes, injected_packets: List[bytes] | None = None) -> bytes:
        # output buffer
        out = bytearray()
         
        # Inject ACKs
        for pkt in (injected_packets or []):
            out.extend(pkt)
        
        # Check Active Dict
        did = self.derive_id(data)
        if did in self.active_dict and self.active_dict[did] == data:
            # OP_RECALL
            out.extend(struct.pack(">B I", OP_RECALL, did))
            # LRU update
            self._touch(did)
            return bytes(out)
        
        # Not in active. 
        # Check Hebbian count
        count = self.obs_counts.get(data, 0) + 1
        self.obs_counts[data] = count
        
        should_propose = (
            count >= MIN_OBSERVATIONS and
            did not in self.pending_dict and
            did not in self.active_dict and
            len(data) <= 256 and # Safety cap
            len(data) >= 8       # Minimum worth compressing
        )
        
        if should_propose:
            # Send PROPOSE
            # Add to pending
            self.pending_dict[did] = data
            out.extend(struct.pack(">B I H", OP_PROPOSE, did, len(data)))
            out.extend(data)
        else:
            # Send LITERAL
            out.extend(struct.pack(">B H", OP_LITERAL, len(data)))
            out.extend(data)
            
        return bytes(out)

    def decode_packet(self, stream: bytes) -> Tuple[bytes, List[bytes], List[int]]:
        """
        Decode stream. Returns (plaintext, acks_to_send, received_ack_ids).
        """
        plaintext = bytearray()
        acks_to_send = []
        received_ack_ids = []
        
        ptr = 0
        while ptr < len(stream):
            op = stream[ptr]
            ptr += 1
            
            if op == OP_LITERAL:
                if ptr + 2 > len(stream): break
                length = struct.unpack(">H", stream[ptr:ptr+2])[0]
                ptr += 2
                if ptr + length > len(stream): break
                data = stream[ptr:ptr+length]
                ptr += length
                plaintext.extend(data)
                
            elif op == OP_PROPOSE:
                if ptr + 6 > len(stream): break
                did, length = struct.unpack(">I H", stream[ptr:ptr+6])
                ptr += 6
                if ptr + length > len(stream): break
                data = stream[ptr:ptr+length]
                ptr += length
                plaintext.extend(data)
                
                # Receiver logic: Verify ID
                expected_id = self.derive_id(data)
                if did == expected_id:
                    self._promote(did, data)
                    # Create OP_ACK packet: OP_ACK + ID + Padding
                    ack_pkt = struct.pack(">B I", OP_ACK, did) + (b"\x00" * 32)
                    acks_to_send.append(ack_pkt) 
                
            elif op == OP_RECALL:
                if ptr + 4 > len(stream): break
                did = struct.unpack(">I", stream[ptr:ptr+4])[0]
                ptr += 4
                if did in self.active_dict:
                    data = self.active_dict[did]
                    plaintext.extend(data)
                    self._touch(did)
                else:
                    raise ValueError(f"NeuralCodec Desync: Unknown ID {did}")
            
            elif op == OP_ACK:
                 if ptr + 36 > len(stream): break # 4 + 32
                 did = struct.unpack(">I", stream[ptr:ptr+4])[0]
                 # h = stream[ptr+4:ptr+36] 
                 ptr += 36
                 received_ack_ids.append(did)
            
            elif op == OP_EVICT:
                 if ptr + 4 > len(stream): break
                 did = struct.unpack(">I", stream[ptr:ptr+4])[0]
                 ptr += 4
                 self._evict(did)
                 
        return bytes(plaintext), acks_to_send, received_ack_ids

    def _promote(self, did: int, data: bytes):
        if len(self.active_dict) >= MAX_ENTRIES:
             # Evict LRU
             oldest = self.lru.popleft()
             del self.active_dict[oldest]
        
        self.active_dict[did] = data
        self.lru.append(did)
        self.total_bytes += len(data)

    def _touch(self, did: int):
        try:
            self.lru.remove(did)
            self.lru.append(did)
        except ValueError:
            pass

    def _evict(self, did: int):
        if did in self.active_dict:
            del self.active_dict[did]
            # remove from lru
            try:
                self.lru.remove(did)
            except ValueError:
                pass

import hmac
import struct
import hashlib
from typing import List, Optional, Tuple
from core.neural_codec import NeuralCodec
try:
    from core.physics_v12 import (
        compute_block_salt,
        derive_keystream_and_permutation,
        inverse_permute,
        permute,
        xor_bytes,
    )
except Exception:
    from core.physics_v12 import (
        compute_block_salt,
        derive_keystream_and_permutation,
        inverse_permute,
        permute,
        xor_bytes,
    )

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()



def crypt_with_bits(
    *, 
    framed: List[int], 
    bits: List[int], 
    session_id: str, 
    nonce: int, 
    ephemeral_salt: int, 
    encrypt: bool
) -> List[int]:
    """
    Core IDRE Stream Cipher logic (XOR + Permutation).
    Uses 'bits' (Field Fingerprint) as the key source.
    """
    block_size = 32
    combined = f"{session_id}:{int(ephemeral_salt)}:{int(nonce)}"

    if encrypt:
        pt = list(framed)
        # PKCS#7-ish padding to block size? logic says: append 0s
        while len(pt) % block_size != 0:
            pt.append(0)
        out: List[int] = []
        for idx in range(len(pt) // block_size):
            chunk = pt[idx * block_size : (idx + 1) * block_size]
            salt = compute_block_salt(bits, combined, idx)
            k_t, pi_t = derive_keystream_and_permutation(salt, block_size)
            out.extend(xor_bytes(permute(chunk, pi_t), k_t))
        return out

    # Decrypt
    ct = list(framed)
    if len(ct) % block_size != 0:
        # Truncate to block boundary? Original logic did this.
        ct = ct[: (len(ct) // block_size) * block_size]
    out = []
    for idx in range(len(ct) // block_size):
        chunk = ct[idx * block_size : (idx + 1) * block_size]
        salt = compute_block_salt(bits, combined, idx)
        k_t, pi_t = derive_keystream_and_permutation(salt, block_size)
        out.extend(inverse_permute(xor_bytes(chunk, k_t), pi_t))
    return out

def derive_mac_key(
    *, 
    bits: List[int], 
    session_id: str, 
    nonce: int, 
    ephemeral_salt: int
) -> bytes:
    """Derive session+packet specific MAC key from Field Fingerprint."""
    bits_bytes = bytes(int(b) & 1 for b in bits)
    ctx = f"{session_id}:{int(ephemeral_salt)}:{int(nonce)}".encode("utf-8")
    return _sha256(b"MACKEY/" + bits_bytes + b":" + ctx)

def encrypt_stream(
    data: bytes,
    *,
    bits: List[int],
    session_id: str,
    nonce: int,
    ephemeral_salt: int,
    pad_bytes: int = 0,
    max_bytes: int = 65535,
    codec: Optional[NeuralCodec] = None,
    injected_packets: Optional[List[bytes]] = None,
) -> List[int]:
    """
    High-level encryption pipeline:
    1. Neural Compress (Optional)
    2. Framing (Length + Data)
    3. Padding
    4. Encryption (crypt_with_bits)
    """
    # 1. Compress / Inject
    if codec:
        data = codec.encode(data, injected_packets=list(injected_packets or []))
        
    if len(data) > max_bytes:
        raise ValueError("plaintext_too_large")

    # 2. Frame
    # Format: [Len (4 bytes)] [Data] [Pad]
    blob = struct.pack(">I", int(len(data))) + data
    
    # 3. Pad (Random bytes)
    pt = [b for b in blob]
    if pad_bytes > 0:
        current_len = len(pt)
        if current_len < pad_bytes:
            padding_needed = pad_bytes - current_len
            import secrets
            padding = [secrets.randbits(8) for _ in range(padding_needed)]
            pt.extend(padding)
            
    return crypt_with_bits(framed=pt, bits=bits, session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt, encrypt=True)

def decrypt_stream(
    payload: List[int],
    *,
    bits: List[int],
    session_id: str,
    nonce: int,
    ephemeral_salt: int,
    codec: Optional[NeuralCodec] = None,
) -> Tuple[Optional[bytes], str, List[bytes]]:
    """
    High-level decryption pipeline:
    1. Decrypt (crypt_with_bits)
    2. Unframe (Read Len)
    3. Neural Decompress (Optional)
    Returns: (blob, reason, acks)
    """
    # 1. Decrypt
    pt = crypt_with_bits(framed=payload, bits=bits, session_id=session_id, nonce=nonce, ephemeral_salt=ephemeral_salt, encrypt=False)
    
    # 2. Unframe
    if len(pt) < 4:
        return None, "payload_too_short", []
    
    data_bytes = bytes(pt)
    try:
        data_len = struct.unpack(">I", data_bytes[:4])[0]
    except Exception:
        return None, "bad_framing", []

    if data_len > len(data_bytes) - 4:
        return None, "truncated_payload", []
        
    actual_data = data_bytes[4 : 4 + data_len]
    
    acks = []
    # 3. Decompress
    if codec:
        try:
            actual_data, acks = codec.decode(actual_data)
        except Exception:
            return None, "codec_error", []
            
    return actual_data, "ok", acks

def seal_stream(
    data: bytes,
    *,
    bits: List[int],
    session_id: str,
    nonce: int,
    ephemeral_salt: int,
    pad_bytes: int = 0,
    aad: bytes = b"",
    max_bytes: int = 65535,
    codec: Optional[NeuralCodec] = None,
    injected_packets: Optional[List[bytes]] = None,
) -> List[int]:
    """
    Full Encrypt + Envelope:
    [Ver(1)] [Nonce(8)] [Salt(8)] [EncryptedStream] [MAC(32)]
    """
    # 1. Encrypt Stream (Compress + Frame + Pad + Encrypt)
    ct_ints = encrypt_stream(
        data,
        bits=bits,
        session_id=session_id,
        nonce=nonce,
        ephemeral_salt=ephemeral_salt,
        pad_bytes=pad_bytes,
        max_bytes=max_bytes,
        codec=codec,
        injected_packets=list(injected_packets or []),
    )
    
    # 2. Derive MAC Key
    key = derive_mac_key(
        bits=bits, 
        session_id=session_id, 
        nonce=nonce, 
        ephemeral_salt=ephemeral_salt
    )
    
    # 3. Calculate MAC
    if aad:
        hargs = bytearray()
        hargs.extend(aad)
        hargs.extend(bytes(ct_ints))
        mac = context_hmac(key, hargs)
    else:
        mac = context_hmac(key, bytes(ct_ints))

    # 4. Construct Envelope
    # Envelope: [Ver(1)] + [Nonce(8)] + [Salt(8)] + [CT] + [MAC(32)]
    out = [1] 
    out.extend([b for b in struct.pack(">Q", int(nonce))])
    out.extend([b for b in struct.pack(">Q", int(ephemeral_salt))])
    out.extend(ct_ints)
    out.extend([b for b in mac])
    return out

def open_stream(
    payload: List[int],
    *,
    bits: List[int],
    session_id: str,
    nonce: int, # Expected nonce (from envelope logic in node) or check against payload?
    ephemeral_salt: int, # Expected salt
    aad: bytes = b"",
    codec: Optional[NeuralCodec] = None,
) -> Tuple[Optional[bytes], str, List[bytes], bytes]: # Returns (pt, reason, acks, tag)
    """
    Full Decrypt + Envelope Check:
    Verifies MAC, Decrypts, Decompresses.
    Returns the MAC 'tag' used for verification to allow chain updates.
    """
    if len(payload) < 1 + 8 + 8 + 32:
        return None, "payload_too_short", [], b""
        
    # Check Version
    if payload[0] != 1:
        return None, "bad_version", [], b""
        
    # MAC Check
    mac_len = 32
    ct_len = len(payload) - 1 - 8 - 8 - mac_len
    if ct_len < 0:
        return None, "payload_too_short", [], b""
        
    received_mac_ints = payload[-mac_len:]
    received_mac = bytes(received_mac_ints)
    ct_ints = payload[1+8+8 : 1+8+8+ct_len]
    
    key = derive_mac_key(
        bits=bits, 
        session_id=session_id, 
        nonce=nonce, 
        ephemeral_salt=ephemeral_salt
    )
    
    if aad:
        hargs = bytearray()
        hargs.extend(aad)
        hargs.extend(bytes(ct_ints))
        expected_mac = context_hmac(key, hargs)
    else:
        expected_mac = context_hmac(key, bytes(ct_ints))
        
    if not hmac.compare_digest(received_mac, expected_mac):
        return None, "mac_mismatch", [], b""
        
    # Decrypt Stream
    pt, reason, acks = decrypt_stream(
        ct_ints,
        bits=bits,
        session_id=session_id,
        nonce=nonce,
        ephemeral_salt=ephemeral_salt,
        codec=codec
    )
    
    return pt, reason, acks, received_mac

def context_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

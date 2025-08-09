# messaging.py
import json, hashlib, binascii
from typing import Dict, Any, List, Tuple
from rsa import generate_keys, encrypt, decrypt, sign, verify  # teammate's module

# ---------- Shared schema ----------
Message = Dict[str, Any]

def make_message(sender: str, receiver: str, body: str, metadata: Dict[str, Any]) -> Message:
    return {
        "senderId": sender,
        "receiverId": receiver,
        "metadata": metadata,
        "body": body,
    }

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

# ---------- Wire helpers for RSA ----------
def rsa_encrypt_to_blocks(pubkey: Tuple[int,int], plaintext: bytes) -> List[str]:
    blocks = encrypt(pubkey, plaintext)
    return [binascii.hexlify(b).decode("ascii") for b in blocks]

def rsa_decrypt_from_blocks(privkey: Tuple[int,int], hex_blocks: List[str]) -> bytes:
    blocks = [binascii.unhexlify(hb.encode("ascii")) for hb in hex_blocks]
    return decrypt(privkey, blocks)

def rsa_sign_hex(privkey: Tuple[int,int], message_bytes: bytes) -> str:
    sig = sign(privkey, message_bytes)
    return binascii.hexlify(sig).decode("ascii")

def rsa_verify_hex(pubkey: Tuple[int,int], message_bytes: bytes, sig_hex: str) -> bool:
    sig = binascii.unhexlify(sig_hex.encode("ascii"))
    return verify(pubkey, message_bytes, sig)

# ---------- Sender: create encrypted+signed message ----------
def create_encrypted_signed_message(
    sender_id: str,
    receiver_id: str,
    sender_private: Tuple[int,int],
    receiver_public: Tuple[int,int],
    key_hint: str,
    plaintext: str,
) -> Message:
    msg_bytes = plaintext.encode("utf-8")
    msg_hash = sha256_hex(msg_bytes)
    sig_hex = rsa_sign_hex(sender_private, msg_bytes)
    ct_blocks_hex = rsa_encrypt_to_blocks(receiver_public, msg_bytes)

    meta = {
        "encoding": "utf-8",
        "cipher": "rsa",
        "signed": True,
        "hash": msg_hash,
        "signature": sig_hex,
        "blockCount": len(ct_blocks_hex),
        "keyHint": key_hint,
    }
    return make_message(sender_id, receiver_id, body=json.dumps({"rsa": ct_blocks_hex}), metadata=meta)

# ---------- Receiver: verify, decrypt, and build signed ack ----------
def process_and_acknowledge(
    incoming: Message,
    sender_public: Tuple[int,int],
    receiver_private: Tuple[int,int],
    receiver_id: str,
    ack_text: str,
    receiver_key_hint: str,
) -> Tuple[str, Message]:
    payload = json.loads(incoming["body"])
    ct_blocks_hex = payload["rsa"]
    recovered = rsa_decrypt_from_blocks(receiver_private, ct_blocks_hex)

    sig_ok = rsa_verify_hex(sender_public, recovered, incoming["metadata"]["signature"])
    hash_ok = (sha256_hex(recovered) == incoming["metadata"]["hash"])
    status = "VALID" if (sig_ok and hash_ok) else "INVALID"

    ack_bytes = ack_text.encode("utf-8")
    ack_hash = sha256_hex(ack_bytes)
    ack_sig_hex = rsa_sign_hex(receiver_private, ack_bytes)

    ack_payload = {
        "originalSignature": incoming["metadata"]["signature"],
        "originalHash": incoming["metadata"]["hash"],
        "replyText": ack_text,
        "replyHash": ack_hash,
        "replyEncryptedHash": ack_sig_hex,
    }
    ack_meta = {
        "encoding": "utf-8",
        "signed": True,
        "ackFor": incoming["metadata"].get("keyHint", "unknown"),
        "keyHint": receiver_key_hint,
    }
    ack_msg = make_message(receiver_id, incoming["senderId"], body=json.dumps(ack_payload), metadata=ack_meta)
    return status, ack_msg

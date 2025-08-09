# main_ack.py
from rsa import generate_keys
from messaging import create_encrypted_signed_message, process_and_acknowledge
import json

def demo_ack():
    # Keys for Alice (sender) and Bob (receiver)
    alice_pub, alice_priv = generate_keys(bits=512)
    bob_pub, bob_priv = generate_keys(bits=512)

    # Alice -> Bob: encrypted + signed
    outgoing = create_encrypted_signed_message(
        sender_id="alice",
        receiver_id="bob",
        sender_private=alice_priv,
        receiver_public=bob_pub,
        key_hint="alice_pub_512",
        plaintext="Hi Bob, ICS 311 signing and ack time.",
    )
    print("\n--- Alice sends to Bob ---")
    print(json.dumps(outgoing, indent=2)[:300], "...")

    # Bob verifies, decrypts, and returns a signed acknowledgement
    status, ack = process_and_acknowledge(
        incoming=outgoing,
        sender_public=alice_pub,
        receiver_private=bob_priv,
        receiver_id="bob",
        ack_text="Ack: received and verified.",
        receiver_key_hint="bob_pub_512",
    )
    print("\nVerification status:", status)
    print("\n--- Bob's signed acknowledgement ---")
    print(json.dumps(ack, indent=2)[:300], "...")

if __name__ == "__main__":
    demo_ack()

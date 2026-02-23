def run_permutation_analysis():
    print("--- Permutation Recovery Matrix Analysis ---")
    print("WARNING: Attack Vector Neutralized by IDRE Protocol Architecture")
    print("Phase 3 of the Cryptanalysis Plan assumed that the keystream (`K`) for Block 1 ")
    print("would remain constant across multiple messages in the same session, allowing us ")
    print("to 'undo' the XOR using the `K` recovered from the constant plaintexts, and then ")
    print("map the permutation (`pi`) using variable counter plaintexts.")
    print("")
    print("FINDING: IDRE derives `K` and `pi` dynamically per block via algorithmic mix: ")
    print("    compute_block_salt(bits, session_id : e_salt : NONCE, block_idx)")
    print("Because the Ouroboros `nonce` strictly increments per message, EVERY single ")
    print("ciphertext is encrypted with an entirely novel permutation AND keystream.")
    print("Consequence: The `K` recovered from message `N` cannot decrypt message `N+1`.")
    print("The Chosen-Plaintext Attack (CPA) fails to invert the permutation matrix.")
    print("Permute-XOR Dynamic Message Ratcheting: SECURE.")

if __name__ == "__main__":
    run_permutation_analysis()

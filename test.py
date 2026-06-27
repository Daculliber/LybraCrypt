from LybraCrypt import LybraCrypt

# 1. Initialization and Setup
# Choose a strong deployment password
passphrase = b"SuperSecurePassword123" 
lybra_file = "system_mapping.lyb"

# Instantiate the framework interface
crypto = LybraCrypt(key=passphrase)

# 2. Keybook Generation (Only needs to be done once per deployment)
# This generates the randomized 5-byte token maps
crypto.generate_lybra(lybra_file, codes_per_byte=1000)

# 3. Reloading for Production Use
# In practice, your application will load the existing .lyb file directly
crypto = LybraCrypt(key=passphrase, lybra_path=lybra_file)

# 4. Data Processing Execution
secret_message = b"Cleartext payload data for secure transit."
print(f"Original Plaintext: {secret_message.decode()}")

# Execute the multi-layer encryption sequence
ciphertext = crypto.encrypt(secret_message)
print(f"Encrypted Ciphertext: {ciphertext}... [Truncated]")

# Execute decryption and signature validation
decrypted_message = crypto.decrypt(ciphertext)
print(f"Decrypted Result: {decrypted_message.decode()}")
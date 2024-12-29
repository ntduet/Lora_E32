import serial
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def aes_decrypt(ciphertext, key1):
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key1, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), AES.block_size)
    return decrypted.decode('utf-8')

# AES Key
key = bytes.fromhex('892679c07fd17954b94fc2625f6fd12d')

# Initialize serial communication
ser = serial.Serial(
    port="/dev/serial0",  # Change to the appropriate port
    baudrate=9600,
    bytesize=serial.EIGHTBITS,
    parity=serial.PARITY_NONE,
    stopbits=serial.STOPBITS_ONE,
    timeout=0.1
)

print("Receiver program started. Press Ctrl+C to stop.")

try:
    while True:
        # Check if there is data available to read
        if ser.in_waiting:
            # Read encrypted data
            encrypted_data = ser.read(48)  # Adjust size based on your data (16 IV + ciphertext)

            if len(encrypted_data) >= AES.block_size:
                try:
                    # Attempt to decrypt the message
                    decrypted_message = aes_decrypt(encrypted_data, key)
                    print(f"Received encrypted message (hex): {encrypted_data.hex()}")
                    print(f"Decrypted message: {decrypted_message}")
                except ValueError:
                    # Ignore messages that cannot be decrypted
                    pass

except KeyboardInterrupt:
    print("\nReceiver program stopped.")
finally:
    ser.close()
    print("Receiver exited.")

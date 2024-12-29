import serial
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

def aes_encrypt(plaintext, key1):
    cipher = AES.new(key1, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    return cipher.iv + ct_bytes  # Append IV to ciphertext for decryption

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

print("Sender program started. Press Ctrl+C to stop.")

try:
    while True:
        # Plaintext message to send
        plaintext = "hello"
        print(f"Original message: {plaintext}")

        # Encrypt the message
        encrypted_message = aes_encrypt(plaintext, key)
        print(f"Encrypted message (hex): {encrypted_message.hex()}")

        # Send encrypted data
        ser.write(encrypted_message)

        time.sleep(2)  # Wait for 2 seconds before sending again

except KeyboardInterrupt:
    print("\nSender program stopped.")
finally:
    ser.close()
    print("Sender exited.")

import socket
import hashlib
import struct
import time

# Helper functions for formatting data
def to_hex(number):
    return hex(number)[2:]

def pad_size(data, size):
    return data.rjust(size * 2, '0')

def reverse_bytes(bytes_hex):
    return ''.join([bytes_hex[i:i+2] for i in range(0, len(bytes_hex), 2)][::-1])

def ascii_to_hex(string):
    return string.encode('utf-8').hex().ljust(24, '0')

def checksum(payload_hex):
    payload_bytes = bytes.fromhex(payload_hex)
    hash1 = hashlib.sha256(payload_bytes).digest()
    hash2 = hashlib.sha256(hash1).hexdigest()
    return hash2[:8]

# Create the payload for a version message
payload = reverse_bytes(pad_size(to_hex(70014), 4))         # Protocol version
payload += reverse_bytes(pad_size(to_hex(0), 8))            # Services
payload += reverse_bytes(pad_size(to_hex(int(time.time())), 8))  # Timestamp
payload += reverse_bytes(pad_size(to_hex(0), 8))            # Remote node services
payload += "00000000000000000000ffff2e13894a"               # Remote node IPv6
payload += pad_size(to_hex(8333), 2)                        # Remote node port
payload += reverse_bytes(pad_size(to_hex(0), 8))            # Local node services
payload += "00000000000000000000ffff7f000001"               # Local node IPv6
payload += pad_size(to_hex(8333), 2)                        # Local node port
payload += reverse_bytes(pad_size(to_hex(0), 8))            # Nonce
payload += "00"                                             # User agent (compact_size)
payload += reverse_bytes(pad_size(to_hex(0), 4))            # Last block

# Create the message header
magic_bytes = 'f9beb4d9'
command = ascii_to_hex('version')                           # Command name
size = reverse_bytes(pad_size(to_hex(len(payload) // 2), 4))  # Payload size
checksum_val = checksum(payload)
header = magic_bytes + command + size + checksum_val

# Combine the header and payload
message = header + payload

# 1. Send Version Message
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("159.203.191.48", 8333))

# Send the version message
sock.send(bytes.fromhex(message))
print("version->")
print(message)
print()

# 2. Receive Version Message
def read_bytes(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket disconnected")
        data += packet
    return data

# Read the message header
magic_bytes = read_bytes(sock, 4).hex()
command = read_bytes(sock, 12).decode('ascii').rstrip('\x00')
size = struct.unpack('<I', read_bytes(sock, 4))[0]  # Little-endian unsigned int
checksum_val = read_bytes(sock, 4).hex()

# Print the message header
print("<-version")
print(f"magic_bytes: {magic_bytes}")
print(f"command:     {command}")
print(f"size:        {size}")
print(f"checksum:    {checksum_val}")

# Read the message payload
payload = read_bytes(sock, size).hex()
print(f"payload:     {payload}")
print()

# 3. Receive Verack Message
magic_bytes = read_bytes(sock, 4).hex()
command = read_bytes(sock, 12).decode('ascii').rstrip('\x00')
size = struct.unpack('<I', read_bytes(sock, 4))[0]
checksum_val = read_bytes(sock, 4).hex()

# Print the message header
print("<-verack")
print(f"magic_bytes: {magic_bytes}")
print(f"command:     {command}")
print(f"size:        {size}")
print(f"checksum:    {checksum_val}")

# Read the message payload (if any)
payload = read_bytes(sock, size).hex()
print(f"payload:     {payload}")
print()

# 4. Send Verack Message
payload = ''  # Verack has no payload
magic_bytes = 'f9beb4d9'
command = ascii_to_hex('verack')
size = reverse_bytes(pad_size(to_hex(len(payload) // 2), 4))
checksum_val = checksum(payload)
verack = magic_bytes + command + size + checksum_val + payload

# Send the verack message
sock.send(bytes.fromhex(verack))
print("verack->")
print(f"magic_bytes: {magic_bytes}")
print(f"command:     verack")
print(f"size:        {int(size, 16)}")
print(f"checksum:    {checksum_val}")
print(f"payload:     {payload}")
print()

# Keep reading messages
while True:
    # Create a buffer to find the next stream of magic bytes
    buffer = b''

    while True:
        byte = sock.recv(1)
        if not byte:
            print("Read a nil byte from the socket. Looks like the remote node has disconnected.")
            exit()

        buffer += byte
        if len(buffer) == 4:
            if buffer.hex() == 'f9beb4d9':
                # Read the full message
                command = read_bytes(sock, 12).decode('ascii').rstrip('\x00')
                size = struct.unpack('<I', read_bytes(sock, 4))[0]
                checksum_val = read_bytes(sock, 4).hex()
                payload = read_bytes(sock, size).hex()

                # Print the message
                print(f"<-{command}")
                print(f"magic_bytes: {buffer.hex()}")
                print(f"command:     {command}")
                print(f"size:        {size}")
                print(f"checksum:    {checksum_val}")
                print(f"payload:     {payload}")
                print()

                # Respond to inv messages with getdata
                if command == "inv":
                    command = "getdata"
                    magic_bytes = 'f9beb4d9'
                    command_hex = ascii_to_hex(command)
                    size_hex = reverse_bytes(pad_size(to_hex(len(payload) // 2), 4))
                    checksum_val = checksum(payload)
                    message = magic_bytes + command_hex + size_hex + checksum_val + payload

                    print(f"{command}->")
                    print(f"magic_bytes: {magic_bytes}")
                    print(f"command:     {command}")
                    print(f"size:        {len(payload) // 2}")
                    print(f"checksum:    {checksum_val}")
                    print(f"payload:     {payload}")
                    print()

                    sock.send(bytes.fromhex(message))

                # Respond to ping messages with pong
                if command == "ping":
                    command = "pong"
                    magic_bytes = 'f9beb4d9'
                    command_hex = ascii_to_hex(command)
                    size_hex = reverse_bytes(pad_size(to_hex(len(payload) // 2), 4))
                    checksum_val = checksum(payload)
                    message = magic_bytes + command_hex + size_hex + checksum_val + payload

                    print(f"{command}->")
                    print(f"magic_bytes: {magic_bytes}")
                    print(f"command:     {command}")
                    print(f"size:        {len(payload) // 2}")
                    print(f"checksum:    {checksum_val}")
                    print(f"payload:     {payload}")
                    print()

                    sock.send(bytes.fromhex(message))

                break
            else:
                buffer = buffer[1:]  # Shift buffer to continue searching for magic bytes
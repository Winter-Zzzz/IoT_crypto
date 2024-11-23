import qrcode
from qrcode.constants import ERROR_CORRECT_L
from typing import List, Tuple
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import secrets
import re

class DeviceDataGenerator:
    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes, bytes]:
        """
        Generate EC private key and both compressed/uncompressed public key
        Returns: (private_key_hex, uncompressed_public_key_hex, compressed_public_key_bytes)
        """
        # Generate EC private key
        private_key = ec.generate_private_key(ec.SECP256R1())
        
        # Get private key bytes
        private_bytes = private_key.private_numbers().private_value.to_bytes(32, 'big')
        
        # Get public key in uncompressed format
        public_key = private_key.public_key()
        public_bytes_uncompressed = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        
        # Get compressed public key
        public_bytes_compressed = public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        
        return (
            private_bytes.hex(),
            public_bytes_uncompressed.hex(),
            public_bytes_compressed
        )

    @staticmethod
    def generate_passcode() -> bytes:
        """Generate 16-byte random passcode"""
        return os.urandom(16)

    @staticmethod
    def create_function_data(func_str: str) -> bytes:
        """Convert function signature to binary format"""
        def get_type_code(type_str: str) -> int:
            return {
                'void': 0x00,
                'string': 0x01,
                'number': 0x02,
                'boolean': 0x03
            }.get(type_str.lower(), 0x00)
        
        # Parse function signature using regex
        match = re.match(r'(\w+)\((.*?)\)\s*->\s*(\w+)', func_str)
        if not match:
            raise ValueError(f"Invalid function signature: {func_str}")
            
        func_name, args_str, return_type = match.groups()
        
        # Parse arguments and convert to type codes
        if args_str:
            arg_types = [get_type_code(arg.strip()) for arg in args_str.split(',')]
        else:
            arg_types = []
        
        # Create function name bytes (18 bytes)
        name_bytes = func_name.encode('ascii')
        name_bytes = name_bytes[:18] + b'\x00' * (18 - len(name_bytes))
        
        # Get return type code
        return_code = get_type_code(return_type)
        
        # Create 16-bit type value
        type_value = 0
        
        # Set return type in lowest 2 bits
        type_value |= return_code & 0x03
        
        # Pack argument types into upper 14 bits
        for i, arg_type in enumerate(arg_types[:7]):  # Max 7 arguments
            type_value |= (arg_type & 0x03) << (14 - (i * 2))
            
        # Split into two bytes
        type_byte1 = (type_value >> 8) & 0xFF
        type_byte2 = type_value & 0xFF
            
        return name_bytes + bytes([type_byte1, type_byte2])

    @staticmethod
    def generate_device_data(function_list: List[str]) -> Tuple[bytes, str, str, str]:
        """
        Generate complete device data and return with keys
        Returns: (device_data, private_key_hex, public_key_hex, passcode_hex)
        """
        # Generate keys
        priv_key_hex, pub_key_hex, compressed_pub = DeviceDataGenerator.generate_keypair()
        
        # Generate passcode
        passcode = DeviceDataGenerator.generate_passcode()
        
        # Combine all data
        device_data = bytearray()
        device_data.extend(compressed_pub)  # 33 bytes compressed public key
        device_data.extend(passcode)        # 16 bytes passcode
        
        # Add function data
        for func in function_list:
            func_data = DeviceDataGenerator.create_function_data(func)
            device_data.extend(func_data)   # 20 bytes per function
            
        return bytes(device_data), priv_key_hex, pub_key_hex, passcode.hex()

def main(function_list: List[str]):
    # Generate device data and keys
    device_data, priv_key, pub_key, passcode = DeviceDataGenerator.generate_device_data(function_list)
    
    # Print key information
    print("\nGenerated Device Information:")
    print(f"Private Key (hex): {priv_key}")
    print(f"Public Key (hex): {pub_key}")
    print(f"Passcode (hex): {passcode}")
    
    # Print device data for verification
    print(f"\nDevice Data (hex): {device_data}")
    
    # Convert binary data to text for QR code
    device_data_text = device_data.decode('latin-1', errors='ignore')
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    
    qr.add_data(device_data_text)
    qr.make(fit=True)
    
    # Save QR code image
    qr_image = qr.make_image(fill_color="black", back_color="white")
    qr_image.save("device_data_qr.png")
    
    print("\nQR code saved as 'device_data_qr.png'")

if __name__ == "__main__":
    # Example function signatures
    functions = [
        "setLED(number,boolean) -> void",  # Should generate type bytes: 0xb0, 0x00
        "getTemp() -> number",             # Should generate type bytes: 0x00, 0x02
        "getStatus() -> string",            # Should generate type bytes: 0x00, 0x01
        "changeColor(string) -> string"
    ]
    
    main(functions)
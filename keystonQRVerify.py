import sys
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional
import cbor2
import hashlib
from pycardano import Address, PaymentVerificationKey

sys.path.insert(0, './py_protocol')
from ur.ur_decoder import URDecoder

def decode_ur(content: List[str]) -> Optional[Any]:
    decoder = URDecoder()
    for part in content:
        decoder.receive_part(part.lower().strip())
    return decoder.result_message() if decoder.is_success() else None

def decode_cardano_request(ur_content: Any) -> Dict[str, Any]:
    return {'type': ur_content.type, 'data': cbor2.loads(ur_content.cbor)}

def parse_derivation_path(path_data: Any) -> str:
    if isinstance(path_data, cbor2.CBORTag) and path_data.tag == 304:
        path_dict = path_data.value
        if isinstance(path_dict, dict) and 1 in path_dict:
            path = path_dict[1]
            return '/'.join(f"{p}'" if hardened else str(p) for p, hardened in zip(path[::2], path[1::2]))
    elif isinstance(path_data, dict) and 1 in path_data:
        path = path_data[1]
        return '/'.join(f"{p}'" if hardened else str(p) for p, hardened in zip(path[::2], path[1::2]))
    return str(path_data)

def format_public_key(key: Any) -> str:
    return key.hex() if isinstance(key, bytes) else str(key)

def decode_address_data(address_data: Any) -> str:
    try:
        decoded = cbor2.loads(address_data)
        if isinstance(decoded, dict) and 'address' in decoded:
            return Address.from_primitive(decoded['address']).encode()
        elif isinstance(address_data, bytes):
            return Address.from_primitive(address_data).encode()
    except Exception as e:
        print(f"Failed to decode address data: {e}")
    return str(address_data)

def print_transaction_details(data: Dict[int, Any]):
    print(f"Request ID: {data.get(1, 'N/A')}")
    sign_data = data.get(2, b'')
    
    print("\nRaw Transaction Data:")
    print(sign_data.hex())
    
    try:
        decoded_sign_data = cbor2.loads(sign_data)
        print("\nDecoded Transaction Structure:")
        print(decoded_sign_data)
        
        tx_body = decoded_sign_data[0]
        print("\nTransaction Body Details:")
        
        # Inputs
        print("\nInputs:")
        for i, input_data in enumerate(tx_body.get(0, []), 1):
            print(f"  Input {i}:")
            print(f"    - TX Hash: {input_data[0].hex()}")
            print(f"    - Index: {input_data[1]}")
        
        # Outputs
        print("\nOutputs:")
        for i, output_data in enumerate(tx_body.get(1, []), 1):
            print(f"  Output {i}:")
            address, amount = output_data
            print(f"    - Address: {decode_address_data(address)}")
            print(f"    - Amount: {amount} lovelace ({amount/1000000:.6f} ADA)")
        
        # Fee
        fee = tx_body.get(2, 0)
        print(f"\nFee: {fee} lovelace ({fee/1000000:.6f} ADA)")
        
        # TTL
        print(f"TTL: {tx_body.get(3, 'N/A')}")
        
        # Additional fields
        for key, value in tx_body.items():
            if key not in {0, 1, 2, 3}:
                print(f"Additional field ({key}): {value}")
        
        # Calculate totals
        total_output = sum(output[1] for output in tx_body.get(1, []))
        total_input = total_output + fee
        print(f"\nTotal Input: {total_input} lovelace ({total_input/1000000:.6f} ADA)")
        print(f"Total Output: {total_output} lovelace ({total_output/1000000:.6f} ADA)")
    
    except Exception as e:
        print(f"Failed to decode transaction body: {e}")
    
    print(f"\nOrigin: {data.get(5, 'N/A')}")

def extract_payload_and_hash(payload: bytes) -> Tuple[Any, Any, str, str]:
    try:
        data = cbor2.loads(payload)
        if isinstance(data, list) and len(data) == 4:
            signature_type, address_data, _, payload_content = data
            extracted_payload = payload_content.decode('utf-8', errors='replace') if isinstance(payload_content, bytes) else str(payload_content)
            message_hash = hashlib.sha256(payload).hexdigest()
            return signature_type, address_data, extracted_payload, message_hash
    except Exception as e:
        print(f"Debug - Exception in extract_payload_and_hash: {e}")
    return None, None, None, None

def print_sign_data_details(data: Dict[int, Any]):
    print(f"Request ID: {data.get(1, 'N/A')}")
    
    payload = data.get(2, b'')
    signature_type, address_data, extracted_payload, message_hash = extract_payload_and_hash(payload)
    
    print(f"\nSignature Type: {signature_type}")
    print(f"\nAddress: {decode_address_data(address_data)}")
    print(f"\nPayload: {extracted_payload}")
    print(f"\nMessage Hash: {message_hash}")
    print(f"\nDerivation Path: {parse_derivation_path(data.get(3, 'N/A'))}")
    print(f"\nOrigin: {data.get(4, 'N/A')}")
    
    public_key = data.get(6, b'')
    print(f"\nPublic Key: {format_public_key(public_key)}")
    
    if isinstance(public_key, bytes):
        try:
            vk = PaymentVerificationKey.from_primitive(public_key)
            vk_dict = vk.to_json()
            print("\nDecoded Verification Key:")
            for key, value in vk_dict.items():
                print(f"  {key.capitalize()}: {value}")
        except Exception as e:
            print(f"Failed to decode public key: {e}")

def main(filename: str):
    try:
        with open(filename) as f:
            content = f.readlines()
    except FileNotFoundError:
        print(f"File '{filename}' not found. Please check the file path.")
        return

    ur = decode_ur(content)
    
    if ur is None:
        print("Failed to decode QR codes. Please check the input.")
        return

    print(f"\nUR type: {ur.type}")
    
    if ur.type.startswith('cardano-'):
        decoded_data = decode_cardano_request(ur)
        print("*" * 60)
        print(f"Decoded {decoded_data['type']}")
        print("*" * 60)
        
        if ur.type == 'cardano-sign-request':
            print_transaction_details(decoded_data['data'])
        elif ur.type == 'cardano-sign-data-request':
            print_sign_data_details(decoded_data['data'])
        else:
            print(f"Unsupported Cardano request type: {ur.type}")
    else:
        print(f"Unsupported UR type: {ur.type}")
    
    print("*" * 60)
    print("Please verify the decoded information.")

if __name__ == "__main__":
    filename = "sample_qr_codes.txt"
    main(filename)
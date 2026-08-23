#!/usr/bin/env python3
"""
# Author: Niels Zondervan from Wallet Recovery NL 
# https://www.walletrecovery.nl
# This tool is freely available under the Apache v2 licence.
# Verus "Truth & Privacy for All"
# Verus main site: https://verus.io/
# People Discord: https://www.verus.io/discord
# 
# A lightweight recovery tool for Verus light‑wallet *.pin* files.
# Features:
  • Brute‑force a list of candidate passwords.
  • Verify that the decrypted seed produces a known address.
  • Run a self‑test that encrypts → decrypts a known seed.
  • Support legacy and modern desktop, imported wif keys from mobile
  • Detection based on mnemonic pattern in decrypted content.
  • Detection based on the file name which is the derived bitcon legacy address
    e.g. abandon...about -> 17152DKcnwezgnRjvmkERPkuXA8FnWicRs.pin
    from the seed_bytes after decoding where bitcoin legacy address is 17152DKcnwezgnRjvmkERPkuXA8FnWicRs
  • Mltiple target addresses can be specified as string or .txt file
  • Supports checking multiple walelts at ones, one wallet per line for input
    file  
  
# Benchmark, around 16 pwds/second/core, decryption is the bottleneck
- might implement speed up at some point using pre-compiled library

###############################################################################
## USAGE EXAMPLES
###############################################################################

# 1) Basic recovery (password list via pipe):
   cat passwords.txt | python verus-recover.py -w wallet.pin -a TARGET_ADDR

# 2) With password file:
   python verus-recover.py -w wallet.pin -a TARGET_ADDR -p passwords.txt

# 3) Interactive password prompt:
   python verus-recover.py -w wallet.pin -a TARGET_ADDR

# 4) Test mode (round-trip encryption test):
   python verus-recover.py --test

 Mode selection:
   python verus-recover.py -w wallet.pin -a ADDRESS -m legacy  # Legacy only
   python verus-recover.py -w wallet.pin -a ADDRESS -m modern  # Modern only
   python verus-recover.py -w wallet.pin -a ADDRESS -m both    # Try both (default)

 Debug output:
   cat passwords.txt | python verus-recover.py -w wallet.pin -a ADDR --debug

 Legacy with compression flag:
   cat passwords.txt | python verus-recover.py -w wallet.pin -a ADDR
   
 Privacy and security: Pease note that printing output of a 
    a wallet to the console or to a file should be handled with care.
    Please use this tool responsibly and not for testing on large wallets
    unless you need to since the output contains your mnemonic, password and
    wif key. 


###############################################################################
"""

import base64
import hashlib
import ecdsa
import base58
import sys
import os
import argparse
import re

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend



###############################################################################
## Commandline argument parsing
###############################################################################

def parse_cli_args() -> argparse.Namespace:
    ## Parse command line arguments and return namespace
    parser = argparse.ArgumentParser(
        description=(
            "Verus wallet recovery – try passwords from a list until the "
            "encrypted .pin file can be decrypted."
        )
    )
    
    parser.add_argument(
        "-w",
        "--wallet-file",
        dest="wallet_file",
        metavar="WALLET.PIN",
        help="Path to the Verus *.pin* wallet file.",
    )
    
    parser.add_argument(
        "-a",
        "--address-source",
        dest="address_source",
        metavar="ADDRESS_OR_FILE",
        help=(
            "Target address, a .txt file containing one address per line, "
            "or '-' to read addresses from STDIN."
        ),
    )
    
    parser.add_argument(
        "-p",
        "--passwords",
        dest="passwords_flag",
        metavar="FILE",
        help="Legacy flag to specify a password file.",
    )
    
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress status messages; only the correct password is printed.",
    )
    
    parser.add_argument(
        "-c"
        "compressed",
        dest="compressed",
        choices=["True","False"],
        default="False",
        help="Overwrite the default uncompressed key-address pair for legacy wallet when imported from mobile",
    )
    
    parser.add_argument(
        "-t",
        "--test",
        action="store_true",
        help="Run the built‑in round‑trip test (encrypt → decrypt) and exit.",
    )
    
    parser.add_argument(
        "-m",
        "--mode",
        dest="mode",
        choices=["legacy", "modern", "both"],
        default="both",
        help=(
            "Wallet mode: 'legacy': bytes -> uncompressed, 'modern':seed_phrase ->electrum_seed-> compressed"
            "both' (try both). Default: desktop modern"
        ),
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print all derivation attempts."
    )
    
    return parser.parse_args()

def electrum_style_seed(seed_phrase: str, passphrase: str = "", iguana: bool = True) -> bytes:
    ## Generate Electrum-style seed from mnemonic phrase
    seed = hashlib.sha256(seed_phrase.encode("utf-8")).digest()
    if iguana:
        ba = bytearray(seed)
        ba[0] &= 248
        ba[31] &= 127
        ba[31] |= 64
        seed = bytes(ba)
    return seed

def load_target_addresses(source: str) -> set[str]:
    '''
    Load target addresses from file (.txt) or split input string on delimiters
    '''
    import re
    if source.lower().endswith('.txt'):
        ## Read from file: one address per line
        stream = open(source, "r", encoding="utf-8")
        try:
            return {line.strip() for line in stream if line.strip()}
        finally:
            stream.close()
    else:
        ## Split single string on _, -, or space delimiters
        return {part.strip() for part in re.split(r'[_\-\s]+', source) if part.strip()}

def apply_iguana_clamp(priv_key: bytes) -> bytes:
    ## Apply Iguana byte clamping to private key
    ba = bytearray(priv_key)
    ba[0] &= 248
    ba[31] &= 127
    ba[31] |= 64
    return bytes(ba)

def extract_address_from_filename(pin_path: str) -> str | None:
    ## Extract address from wallet filename (supports Verus R/V/Z and Bitcoin 1)
    filename = os.path.basename(pin_path)
    filename_no_ext = os.path.splitext(filename)[0]
    ## Pattern for Verus addresses: starts with R/V/Z, 33-34 base58 chars
    verus_addr_pattern = r'[VRZ][1-9A-HJ-NP-Za-km-z]{33,34}'
    verus_addr_pattern = r'[VRZ][1-9A-HJ-NP-Za-km-z]{33,34}'
    ## Pattern for Bitcoin legacy addresses: starts with 1, 33-34 base58 chars
    btc_addr_pattern = r'1[1-9A-HJ-NP-Za-km-z]{32,34}'
    verus_match = re.search(verus_addr_pattern, filename_no_ext)
    btc_match = re.search(btc_addr_pattern, filename_no_ext)
    if verus_match:
        extracted = verus_match.group(0)
        print(f"[INFO] Found Verus address in filename: {extracted}")
        return extracted
    if btc_match:
        extracted = btc_match.group(0)
        print(f"[INFO] Found Bitcoin address in filename: {extracted}")
        return extracted
    ## Also check if filename starts with address
    parts = filename_no_ext.split('_')
    if parts and re.match(r'^[VRZ][1-9A-HJ-NP-Za-km-z]{33,34}$', parts[0]):
        print(f"[INFO] Found address as first part: {parts[0]}")
        return parts[0]
    if parts and re.match(r'^1[1-9A-HJ-NP-Za-km-z]{33,34}$', parts[0]):
        print(f"[INFO] Found address as first part: {parts[0]}")
        return parts[0]
    return None



def derive_btc_address(priv_key: bytes, compressed: bool = True) -> tuple[str, str | None]:
    ## Derive Bitcoin legacy P2PKH address from private key
    priv_key = priv_key[:32]
    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x().to_bytes(32, "big")
    y = vk.pubkey.point.y().to_bytes(32, "big")
    if compressed:
        prefix_pk = b"\x02" if (vk.pubkey.point.y() % 2 == 0) else b"\x03"
        pub_key = prefix_pk + x
    else:
        pub_key = b"\x04" + x + y
    h160 = hashlib.new("ripemd160", hashlib.sha256(pub_key).digest()).digest()
    payload = b"\x00" + h160  ## Bitcoin mainnet prefix (0x00)
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum).decode()
    return address


###############################################################################
## DECRYPTION
###############################################################################
def encrypt_pin_legacy(plaintext: bytes, password: str, salt: str, rounds: int = 300000) -> str:
    '''
    Password is hashed with PBKDF2_HMAC_SHA256 with 300_000 rounds
    Encrypt content with AES-CBC using derived key and IV
    Returns base64-encoded ciphertext matching legacy .pin format
    '''
    ## PKCS7 padding
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    salt_bytes = salt.encode()
    ## Password key stretching
    key_iv = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, rounds, dklen=48)
    key = key_iv[:32]
    iv = key_iv[32:]
    ## Use key to encrypt content
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    ## Encode for .pin file storage
    return base64.b64encode(ciphertext).decode()

def decrypt_pin_legacy(enc_data_b64: str, password: str, salt: str, rounds: int = 300000) -> bytes:
    '''
    Passwords is hashed with PBKDF2_HMAC_SHA256 password with 300_000 rounds
    Decrypt content with AES-CBC 300_000 rounds
    Decrypt legacy returns seed_bytes of which seed_bytes[0:32] = priv_key
    '''
    ## Decrypt legacy-format .pin file using AES-CBC
    ciphertext = base64.b64decode(enc_data_b64)
    salt_bytes = salt.encode()
    ## Password key stretching
    key_iv = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, rounds, dklen=48)
    key = key_iv[:32]
    iv = key_iv[32:]
    ## Used key to decrypt content
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    ## removes padding
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

def decrypt_pin_modern(pin_line_parts: list[str], password: str, rounds: int = 300_000) -> str:
    '''
    Passwords is hashed with PBKDF2_HMAC_SHA256 password with 300_000 rounds
    Decrypt content withencrypted with AES-CBC
    Decrypt modern-format .pin file with separate IV and salt
    content is mnemonic string UTF-8
    '''
    enc_data_b64 = pin_line_parts[0]
    iv_hex = pin_line_parts[1]
    salt_hex = pin_line_parts[2]
    try:
        ciphertext = base64.b64decode(enc_data_b64)
    except Exception as e:
        raise ValueError(f"Invalid base64 in parts[0]: {e}")
    if len(ciphertext) == 0:
        raise ValueError("Empty ciphertext in parts[0]")
    if not iv_hex or len(iv_hex) < 32:
        raise ValueError(f"Missing or invalid IV in parts[1]")
    iv = bytes.fromhex(iv_hex[:32])
    if not salt_hex:
        raise ValueError("Missing salt in parts[2]")
    try:
        salt_bytes = bytes.fromhex(salt_hex)
    except ValueError:
        salt_bytes = salt_hex.encode()
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, rounds, dklen=32)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    ## Handles padding, but is permissive
    if len(decrypted) == 0:
        return decrypted
    pad_len = decrypted[-1]
    if pad_len > len(decrypted) or pad_len == 0:
        return decrypted
    return decrypted[:-pad_len]

###############################################################################
## Address Derivation
###############################################################################

def derive_verus_address(
    priv_key: bytes,
    compressed: bool = True,
    return_wif: bool = False
) -> tuple[str, str | None]:
    ## Derive Verus address and optional WIF from private key
    priv_key = priv_key[:32]

    sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    x = vk.pubkey.point.x().to_bytes(32, "big")
    y = vk.pubkey.point.y().to_bytes(32, "big")

    if compressed:
        prefix_pk = b"\x02" if (vk.pubkey.point.y() % 2 == 0) else b"\x03"
        pub_key = prefix_pk + x
    else:
        pub_key = b"\x04" + x + y

    h160 = hashlib.new("ripemd160", hashlib.sha256(pub_key).digest()).digest()
    payload = b"\x3c" + h160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    address = base58.b58encode(payload + checksum).decode()

    wif_key = None
    if return_wif:
        extended_key = b"\xBC" + priv_key
        if compressed:
            extended_key += b"\x01"
        checksum_wif = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
        wif_key = base58.b58encode(extended_key + checksum_wif).decode()

    return (address, wif_key)

def is_valid_wif(s: str, prefix_byte: bytes = b"\xBC") -> str | bool:
    ## Validate WIF key format and checksum
    if len(s) < 50 or len(s) > 53:
        return False
    try:
        decoded = base58.b58decode(s)
    except Exception:
        return False
    if len(decoded) == 38:
        if decoded[0:1] != prefix_byte:
            return False
        if decoded[33] != 0x01:
            return False
        payload = decoded[:34]
        checksum = decoded[34:]
    elif len(decoded) == 37:
        if decoded[0:1] != prefix_byte:
            return False
        payload = decoded[:33]
        checksum = decoded[33:]
    else:
        return False
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        return False
    return True

def private_key_to_wif(private_key_bytes: bytes, compressed: bool = False) -> str:
    ## Convert raw private key bytes to WIF format
    prefix = b"\xBC"
    extended_key = prefix + private_key_bytes[:32]
    
    if compressed:
        extended_key += b"\x01"
    
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    final_key = extended_key + checksum
    
    return base58.b58encode(final_key).decode()

def validate_wif(wif_string: str) -> tuple[bytes | None, bool | None]:
    '''
    Validate WIF key and return (private_key_bytes, is_compressed)
    Returns (None, None) if not a valid WIF key
    '''
    import hashlib
    import base58
    
    ## Basic length check
    if len(wif_string) < 50 or len(wif_string) > 53:
        return None, None
    
    try:
        decoded = base58.b58decode(wif_string)
    except Exception:
        return None, None
    
    ## Compressed WIF: 38 bytes = prefix(1) + key(32) + 0x01(1) + checksum(4)
    if len(decoded) == 38:
        if decoded[0] != 0x80:
            return None, None
        if decoded[33] != 0x01:
            return None, None
        priv_key = decoded[1:33]
        payload = decoded[:34]
        checksum = decoded[34:]
        is_compressed = True
    
    ## Uncompressed WIF: 37 bytes = prefix(1) + key(32) + checksum(4)
    elif len(decoded) == 37:
        if decoded[0] != 0x80:
            return None, None
        priv_key = decoded[1:33]
        payload = decoded[:33]
        checksum = decoded[33:]
        is_compressed = False
    else:
        return None, None
    
    ## Verify checksum (double SHA256)
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        return None, None
    
    return priv_key, is_compressed


###############################################################################
## Self Test
###############################################################################

def run_self_test():
    '''
    Test full round-trip: seed_phrase → encrypt → .pin format → decrypt → verify
    Compares our encryption output against real .pin file formats
    '''
    
    print("\n" + "=" * 60)
    print("ROUND-TRIP TEST: Legacy + Modern Wallet Encryption")
    print("=" * 60)
    
    seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    password = "Test123"
    rounds = 300_000
    
    ## REAL .PIN FILE EXAMPLES FROM USER
    legacy_pin_content = "vd45Tsusd2qGFMS+0nl/OP5R4L/8largZGm8rhtx1gRRqeNYBdIuTpv0FghFWcikDeY0Hg95wWUdeHaLkLKL35ooMWMkY4e6t4ATMTbhz0E=$3ytdP9HgrZUV$a97bd8418fbc7321d62a083743de4c77$74ad5adbf8b19a1de95f24cce8c23edb$300000$cbc"
    modern_pin_content = "r6wi8O4kTEat46rTkcIYc3HimLw9d0UbNbkDmRqFGOCS4nVaZn0SUlMZ7V3vACHi8mkNhZFRkMEgJpXJrXXMIGkOpL4z3A9/BHGYp7RzeZ9W5z819Cyf/Rm4uKPEwQCu$5c98a53f093136911c3ba3d65eee7548$txiTSB+evKEG$bdfd6fcfd2e354e7bfcf3f51ae4ba4563f6d9d2ca54beab84b9e9035032b7862$300000$cbc"
    
    ## === PARSE REAL .PIN FILES ===
    print("\n--- PARSING REAL .PIN FILES ---")
    
    legacy_parts = legacy_pin_content.split("$")
    print(f"\nLegacy .pin parts: {len(legacy_parts)}")
    for i, p in enumerate(legacy_parts):
        print(f"  [{i}] '{p[:40]}'...")
    
    modern_parts = modern_pin_content.split("$")
    print(f"\nModern .pin parts: {len(modern_parts)}")
    for i, p in enumerate(modern_parts):
        print(f"  [{i}] '{p[:40]}'...")
    
    ## === LEGACY WALLET TEST ===
    print("\n--- LEGACY WALLET ROUND-TRIP ---")
    
    seed_bytes = electrum_style_seed(seed_phrase)
    print(f"Seed bytes: {len(seed_bytes)} bytes, first 8: {seed_bytes[:8].hex()}")
    
    salt_legacy = legacy_parts[1]
    iv_hex_legacy = legacy_parts[3]
    rounds_legacy = int(legacy_parts[4])
    
    enc_b64_legacy = legacy_parts[0]
    try:
        decrypted_legacy = decrypt_pin_legacy(enc_b64_legacy, password, salt_legacy, rounds_legacy)
        print(f"Decrypted bytes: {len(decrypted_legacy)} bytes")
        
        recovered_priv_key = decrypted_legacy[:32]
        addr_uncomp, _ = derive_verus_address(recovered_priv_key, compressed=False)
        expected_address = "RYZ4CNBPUdCzsbzZztTy6L6oQ65isvdi9e"
        
        if addr_uncomp == expected_address:
            print(f"✅ Legacy decryption successful")
            print(f"   Address matches: {addr_uncomp}")
            legacy_passed = True
        else:
            print(f"❌ Legacy address mismatch")
            print(f"   Expected: {expected_address}")
            print(f"   Got: {addr_uncomp}")
            legacy_passed = False
    except Exception as e:
        print(f"❌ Legacy decryption failed: {e}")
        legacy_passed = False
    
    ## === MODERN WALLET TEST ===
    print("\n--- MODERN WALLET ROUND-TRIP ---")
    
    ## EXACTLY like production code: split on "$", pass parts directly
    parts = modern_pin_content.split("$")
    rounds_modern = int(parts[4])
    
    print(f"Parts count: {len(parts)}")
    print(f"Rounds: {rounds_modern}")
    
    try:
        ## Pass parts directly to decrypt_pin_modern - no modifications!
        decrypted_modern = decrypt_pin_modern(parts, password, rounds_modern)
        print(f"Decrypted bytes: {len(decrypted_modern)} bytes")
        print(f"First 20 bytes: {decrypted_modern[:20].hex()}")
        
        try:
            decrypted_seed_phrase = decrypted_modern.decode('utf-8')
            print(f"Decrypted seed phrase: {decrypted_seed_phrase[:50]}...")
            
            if seed_phrase in decrypted_seed_phrase:
                print(f"✅ Modern decryption successful")
                modern_passed = True
                
                seed_bytes_recovered = electrum_style_seed(decrypted_seed_phrase.strip())
                priv_key_recovered = seed_bytes_recovered[:32]
                addr_comp, _ = derive_verus_address(priv_key_recovered, compressed=True)
                print(f"Recovered address: {addr_comp}")
            else:
                print(f"❌ Modern seed phrase mismatch")
                print(f"   Expected to contain: {seed_phrase[:20]}...")
                modern_passed = False
        except UnicodeDecodeError as ue:
            print(f"❌ Modern decryption produced invalid UTF-8: {ue}")
            print(f"   Debug: First 40 bytes: {decrypted_modern[:40].hex()}")
            modern_passed = False
    except Exception as e:
        print(f"❌ Modern decryption failed: {e}")
        import traceback
        traceback.print_exc()
        modern_passed = False
    
    ## Final summary
    print("\n" + "=" * 60)
    print("TEST RESULTS")
    print("=" * 60)
    
    print(f"Legacy wallet:  {'✅ PASSED' if legacy_passed else '❌ FAILED'}")
    print(f"Modern wallet:  {'✅ PASSED' if modern_passed else '❌ FAILED'}")
    
    if legacy_passed and modern_passed:
        print("\n✅ ALL TESTS PASSED\n")
        sys.exit(0)
    else:
        print("\n❌ SOME TESTS FAILED\n")
        sys.exit(1)
        
###############################################################################
## ADD-ONN FUNCTIONALITY, NOT CRITICAL
###############################################################################

try:
    import qrcode
    import json
    import requests
    def print_qr_terminal(data: str, invert: bool = True, border: int = 1) -> None:
        """
        Generate and print a QR code for the given string in the terminal as ASCII.

        Parameters:
            data (str): The text or URL to encode in the QR code.
            invert (bool): Whether to invert colours for better contrast in terminal.
            border (int): Border size around the QR code.
        """
        qr = qrcode.QRCode(border=border)
        qr.add_data(data)
        qr.make(fit=True)
        qr.print_ascii(invert=invert)   
        
        def get_address_balance(address):
            """
            #curl --silent --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getaddressbalance", "params": [{"addresses": ["Verus Coin Foundation@"],"friendlynames": true}] }' -H 'content-type: text/plain;' https://api.verus.services | jq .
            Fetch the balance of a Verus address using the public RPC endpoint.

            Args:
                address (str): The Verus address or VerusID (e.g., "Verus Coin Foundation@").

            Returns:
                dict: The JSON response from the RPC endpoint.
            """
            url = "https://api.verus.services"
            headers = {'content-type': 'application/json'}
            payload = {
                "jsonrpc": "1.0",
                "id": "curltest",
                "method": "getaddressbalance",
                "params": [{"addresses": [address], "friendlynames": True}]
            }

            try:
                response = requests.post(
                    url,
                    data=json.dumps(payload),
                    headers=headers,
                )
                response.raise_for_status()  # Raise an error for bad status codes
                return response.json()
            except requests.exceptions.RequestException as e:
                print(f"Error making RPC call: {e}")
                return {}
            #curl --silent --data-binary '{"jsonrpc": "1.0", "id":"curltest", "method": "getaddressbalance", "params": [{"addresses": ["Verus Coin Foundation@"],"friendlynames": true}] }' -H 'content-type: text/plain;' https://api.verus.services | jq .
except:
    pass
        
###############################################################################
## Main Looop
###############################################################################
if __name__ == "__main__":
    
    ###########################################################################
    ## 1) a) Parse arguments b) sload target addresses c) load passwords
    ###########################################################################
    args = parse_cli_args()
    ## Wallet mode 'legacy','modern',default:'both'
    mode = args.mode
    
    ## Run test of all functions, exit after testing
    if args.test:
        run_self_test()
        
    ## b) Store target addresses
    targets = set()
    if args.address_source:
        targets = load_target_addresses(args.address_source)
    ## Add target address based on PubKey -> address in filename (legacy only)
    if args.wallet_file:
        extracted = extract_address_from_filename(args.wallet_file)
        if extracted:
            targets.add(extracted)
            check_btc_address = {t for t in targets if t.startswith('1')}
            if args.debug:
                print(f"[INFO] Added address from filename: {extracted}")
    ## Legacy wallets require user or file based target address to detect pwd
    if not targets and mode == 'legacy':
        sys.stderr.write("[WARNING] No target address specified\n")
    
    ## Get password(s) from a) parameter, b) text file or c) STDIN (best option)
    if args.passwords_flag and ".txt" not in args.passwords_flag:
        passwords = [args.passwords_flag]
    elif args.passwords_flag:
        with open(args.passwords_flag, "r", encoding="utf-8") as pw_f:
            passwords = [ln.rstrip("\r\n") for ln in pw_f if ln.strip()]
    else:
        if not sys.stdin.isatty():
            passwords = [ln.rstrip() for ln in sys.stdin.readlines() if ln.strip()]
        else:
            passwords = [input("Password: ")]
    
    ## Load wallet file
    if not args.wallet_file:
        sys.stderr.write("Error: no wallet file (-w required)\n")
        sys.exit(1)
    with open(args.wallet_file, "r", encoding="utf-8") as f:
        pin_lines = [ln.strip() for ln in f if ln.strip()]
    
    ## Parse wallet content, print output
    if args.debug and pin_lines:
        parts = pin_lines[0].split("$")
        if len(parts) >= 6:
            print(f"\n[INFO] .pin format:")
            print(f"  Enc:  {parts[0][:40]}...")
            print(f"  IV:   {parts[1]} ({len(parts[1])//2} bytes)")
            print(f"  Salt: {parts[2]} ({len(parts[2])} chars)")
            print(f"  Rounds: {parts[4]}")
            print(f"  Method: {parts[5]}")
            print(f"  Mode:   {args.mode}")
    
    found = 0
    total_passwords = len(passwords)
    
    ###########################################################################
    ## 2) 
    ## a) Loop over the wallet file lines, 
    ## b) Test passwords to decrypt
    ## c) Check against target addresses and print output
    ## d) Print output
    ###########################################################################
    ## a) Loop over wallet file lines, allows for multiple wallets cracking
    for line_no, pin_line in enumerate(pin_lines, start=1):
        if pin_line.startswith("#"):
            continue
        
        parts = pin_line.split("$")
        if len(parts) < 6:
            continue
        
        enc_data_b64 = parts[0]
        salt = parts[1]
        iv = parts[3]
        rounds = int(parts[4])
        
        if args.debug:
            print(f"\n[DEBUG] Wallet #{line_no}, Mode: {args.mode}, Rounds: {rounds}")
        ## b) Loop over passwords, try decrypt .pin file and derive correct address
        for pwd_idx, pwd in enumerate(passwords, start=1):
            if not pwd:
                continue
            
            try:
                ## Decrypt with selected mode (single path, no redundancy)
                decrypted_modern = None
                decrypted_legacy = None
                is_modern = False
                is_legacy = False
                method_found = None
                found_match = None
                
                ## Initialize result variables upfront to avoid false positives
                seed_phrase = None
                legacy_addr_comp = None
                legacy_addr_uncomp = None
                modern_addr_comp = None
                modern_addr_uncomp = None
                
                ## MODERN
                if args.mode in ("both", "modern"):
                    try:
                        decrypted_modern = decrypt_pin_modern(parts, pwd, rounds)
                        is_modern = True
                        method_found = "MODERN"
                    except:
                        if args.mode == "modern":
                            continue
                ## LEGACY
                if args.mode in ("both", "legacy"):
                    try:
                        decrypted_legacy = decrypt_pin_legacy(enc_data_b64, pwd, salt, rounds)
                        is_legacy = True
                        method_found = "LEGACY" 
                    except:
                        if args.mode == "legacy":
                            continue
                              
                ## DETECTION METHOD 1A: detect mnemonic like patter in decrypted
                if is_modern:               
                    try:
                        seed_phrase = decrypted_modern.decode('utf-8').strip()
                        space_count = seed_phrase.count(' ')
                        if any(seed_phrase[i] == ' ' for i in range(3, 9)):
                            ## Detection based on content matching mnemonic pattern
                            ## Meaning a string that contains spaces like a mnemonic
                            space_count = seed_phrase.count(' ')
                            ## DETECTION METHOD 1: mnemonic based on regular space count
                            ## Only works for modern wallets since they contain mnemonic string
                            ## Matches pattern of a mnemonic
                            if space_count > 10 and space_count < 24:
                                ## Since a mnemonic is detected, derive from mnemonic
                                seed_bytes = electrum_style_seed(seed_phrase)
                                priv_key_modern=seed_bytes[:32]
                                target_addr,target_wif = derive_verus_address(priv_key_modern, compressed=True, return_wif=True)
                                found_match =True
                                print(f"{'#'*40}")
                                print(f"PASSWORD {pwd}| POTENTIAL MNEMONIC DETECTED!")
                                print(f"Seed phrase: {seed_phrase}")

                        ## DETECTION METHOD 1B: Detect WIF key in modern wallet
                        ## Detect if compression, derive target_address accodingly
                        try:
                            ## If not a WIF key, None, None will be returned
                            priv_key,compressed = validate_wif(seed_phrase)
                            if compressed == True:
                                priv_key_modern  = priv_key
                            if compressed == False:
                                priv_key_legacy  = priv_key                        
                            ## Only if wif_key was detected, return target is hit
                            if priv_key!=None:
                                target_address,target_wif = derive_verus_address(priv_key_modern, compressed=compressed, return_wif=True)
                                found_match =True    
                        ## If WIF does not work out
                        except: 
                            pass         
                    ## If not mnemonic or WIF, just continue with regular checks
                    except:
                        pass
                        
                            
                ## DETECTION METHOD 2: btc address in .pin file name
                ## Newer wallet .pin files contain btc legacy address as file name    
                if check_btc_address and is_modern:
                    try:
                        seed_bytes_modern = electrum_style_seed(seed_phrase)
                        priv_key = seed_bytes_modern[0:32]
                        btc_addr = derive_btc_address(priv_key)
                        ## For now assume that wallets with bitcoin address in name are modern, is that correct?
                        target_address_comp,target_wif_comp = derive_verus_address(priv_key_modern, compressed=True, return_wif=True)
                        target_address_uncomp,target_wif_uncomp = derive_verus_address(priv_key_modern, compressed=False, return_wif=True)
                        found_match =True
                        if btc_addr in targets:
                            target_wif = private_key_to_wif(priv_key_legacy,compressed=True)
                            print(f"PASSWORD FOUND BASED ON BTC ADDRESS IN FILE NAME")
                            print(f"BTC legacy: '{btc_addr}'.pin")
                            print(f"Password:  {pwd}")
                            print(f"Potential compressed addres   |WIF pair: {target_address_comp} | {target_wif_comp}")
                            print(f"Potential un-compressed addres|WIF: {target_address_uncomp} | {target_wif_uncomp}")
                    except:
                        pass
                if check_btc_address and is_legacy:
                    try:
                        seed_bytes_modern = electrum_style_seed(seed_phrase)
                        priv_key = seed_bytes_modern[0:32]
                        
                        btc_addr = derive_btc_address(priv_key)
                        if btc_addr in targets:
                            print(f"PASSWORD FOUND BASED ON BTC ADDRESS IN FILE NAME")
                            print(f"BTC legacy: '{btc_addr}'.pin")
                            print(f"Password:  {pwd}")
                    except:
                        pass 
                ## LEGACY: ADDRESS CHECK in TARGETS
                if is_legacy and len(decrypted_legacy) >=32:
                    seed_bytes_legacy = decrypted_legacy
                    priv_key_legacy = seed_bytes_legacy[:32]
                    ## First check uncompressed keys since most legacy are uncompressed
                    legacy_addr_uncomp, legacy_wif_uncomp = derive_verus_address(priv_key_legacy, compressed=False, return_wif=False)
                    ## Check if address in targets
                    if legacy_addr_uncomp in targets:
                        target_addr = legacy_addr_uncomp 
                        target_wif = private_key_to_wif(priv_key_legacy,compressed=False)
                        found_match =True
                    ## If uncompressed key not in target, check for uncompressed
                    ## This accounts for rare case of imported mobile wif key in legacy wallet
                    else:
                        legacy_addr_comp, legacy_wif_comp = derive_verus_address(priv_key_legacy, compressed=True, return_wif=False)
                        if legacy_addr_comp in targets:
                            target_addr = legacy_addr_comp 
                            target_wif = private_key_to_wif(priv_key_legacy,compressed=True)
                            found_match =True
                            

                ## MODERN: ADDRESS CHECK in TARGETS
                if is_modern:
                    seed_phrase = decrypted_modern.decode('utf-8').strip()
                    seed_bytes_modern = electrum_style_seed(seed_phrase)
                    priv_key_modern = seed_bytes_modern[:32]
                    ## First check compressed keys since modern wallet uses compressed keys
                    modern_addr_comp, modern_wif_comp = derive_verus_address(priv_key_modern, compressed=True, return_wif=False)
                    if modern_addr_comp in targets:
                        target_addr = modern_addr_comp
                        target_wif = private_key_to_wif(priv_key_modern,compressed=True)
                        found_match =True
                    ## If compressed key not in target, check for uncompressed
                    ## This accounts for rare case of imported legacy wif in modern wallet
                    else:
                        modern_addr_uncomp, modern_wif_uncomp = derive_verus_address(priv_key_modern, compressed=False, return_wif=False)
                        if modern_addr_uncomp in targets:
                            target_addr = modern_addr_uncomp
                            target_wif = private_key_to_wif(priv_key_modern,compressed=False)
                            found_match =True
                
                
                ## If found, return results to use            
                if found_match:
                    print(f"\n{'#'*40}")
                    print(f"PASSWORD FOUND!")
                    print(f"Password:  {pwd}")
                    if seed_phrase!=None:
                        print(f"Seed phrase: {seed_phrase}")
                    print(f"Wallet type: {method_found}")
                    print(f"Address:   {target_addr}")
                    print(f"WIF:       {target_wif}")
                    try:
                        print_qr_terminal(target_wif)
                    except:
                        print("Install 'pip install qrcode[pil]' for QR code")
                    try:
                        balance_json = get_address_balance(target_addr)
                        print(f"Balance: {balance_json}")
                    except:
                        print("To get balance, run 'pip install request")    
                    print(f"{'#'*40}\n")
                    found += 1
                    break  ## Only breaks inner password loop
                
            except Exception as e:
                if args.debug:
                    print(f"[DEBUG] '{pwd}' failed: {e}")
                continue    
    if not found:
        sys.exit(1)

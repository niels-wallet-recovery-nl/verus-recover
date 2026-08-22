# Verus Wallet Recovery Tool

A lightweight python based recovery tool for Verus light-wallet `.pin` files. 
Brute-force passwords and recover wallet access. 

## Features

- Brute-force password recovery for `.pin` files
- Supports Legacy and Modern wallet formats (desktop/mobile)
- Detection based on mnemonic pattern in decrypted content
- Automatic address detection from `.pin` filename
- Target address verification (single address or file)
- Round-trip encryption test mode
- Bitcoin legacy address extraction from filenames

## Requirements

bash pip install cryptography ecdsa base58
Optional: for QR codes and balance lookup

pip install qrcode[pil] requests
Usage
Basic Recovery (password list via pipe)
cat passwords.txt | python verus-recover.py -w wallet.pin -a TARGET_ADDR
With Password File
python verus-recover.py -w wallet.pin -a TARGET_ADDR -p passwords.txt
Interactive Password Prompt
python verus-recover.py -w wallet.pin -a TARGET_ADDR
Mode Selection
# Legacy only
python verus-recover.py -w wallet.pin -a ADDR -m legacy

# Modern only
python verus-recover.py -w wallet.pin -a ADDR -m modern

# Try both (default)
python verus-recover.py -w wallet.pin -a ADDR -m both
Test Mode (round-trip encryption test)
python verus-recover.py --test
Debug Output
cat passwords.txt | python verus-recover.py -w wallet.pin -a ADDR --debug
Multiple Target Addresses
# From file (one address per line)
python verus-recover.py -w wallet.pin -a addresses.txt

# From filename (auto-extract)
python verus-recover.py -w 17152DKcnwezgnRjvmkERPkuXA8FnWicRs.pin
Examples
Scenario	Command
Recover legacy wallet	`cat passwords.txt
Recover modern wallet	`cat passwords.txt
Auto-detect mode	`cat passwords.txt
Performance

    Approximately 16 passwords/second/core
    Decryption is the bottleneck (300,000 PBKDF2 rounds)

Security Warning

⚠️ Handle output carefully - The tool may print your mnemonic, password, and WIF key to console. Use responsibly and avoid testing on large wallets unless necessary.
License

Apache v2. Free software.

Author: Niels Zondervan, Wallet Recovery NL
https://www.walletrecovery.nl
https://verus.io

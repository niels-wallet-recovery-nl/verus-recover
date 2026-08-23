# Verus Wallet Recovery Tool

A lightweight python based recovery tool for Verus light-wallet `.pin` files. 
Brute-force passwords and recover wallet access. The python code contains easy to copy and reuse functions for common operations such as .pin file encryption, decryption, verus_address generation, wif-key generation.

<img width="1776" height="802" alt="image" src="https://github.com/user-attachments/assets/0dd5c9f5-ddd7-420d-82a0-5e5809f3cb02" />


## Features

- Brute-force password recovery for `.pin` files
- Supports Legacy and Modern wallet formats (desktop:legacy,modern and imported mobile wif-key)
- Detection based on mnemonic pattern in decrypted content
- Detection of UTF-8 bytes of a imported WIF key in file
- Automatic address detection from `.pin` filename
- Target address verification (single address or file)
- Round-trip encryption test mode
- Bitcoin legacy address extraction from filename, correct decryption detection based on {legacy_btc}.pin name
- Optional 1: Show wallet WIF as text based QR code for easy scanning
- Optional 2: Scan wallet, show balance

## Requirements

bash pip install cryptography ecdsa base58
Optional: for QR codes and balance lookup
    
    pip install qrcode[pil] requests
**Usage**
Basic Recovery (password list via pipe)
    
    cat passwords.txt | python verus-recover.py -w wallet.pin -a TARGET_ADDR
**With Password File**
    
    python verus-recover.py -w wallet.pin -a TARGET_ADDR -p passwords.txt
Interactive Password Prompt
    
    python verus-recover.py -w wallet.pin -a TARGET_ADDR
Mode Selection `-m', for potential higher performance [legacy, modern, both]
    
    python verus-recover.py -w wallet.pin -a ADDR -m legacy
    
    python verus-recover.py -w wallet.pin -a ADDR -m modern

**Try both modes (default)**

    python verus-recover.py -w wallet.pin -a ADDR -m both
**Test Mode (round-trip encryption test)**

    python verus-recover.py --test
**Debug Output**

    cat passwords.txt | python verus-recover.py -w wallet.pin -a ADDR --debug
**Multiple Target Addresses**
**From file (one address per line)**

    python verus-recover.py -w wallet.pin -a addresses.txt

No target address needs to be provided in most cases. .pin files that start with `1...` are essentialy bitcoin addressed derived from the wallet and used as file name. This address can be used to check successful decryption.
Example:

    python verus-recover.py -w 17152DKcnwezgnRjvmkERPkuXA8FnWicRs.pin

## Performance benchmark
-m modern: 33/passwords/second/core
-m legacy: 17/passwords/second/core
-m   both: 11/passwords/second/ core
Approximately 16 passwords/second/core.
Decryption is the bottleneck (300,000 PBKDF2 rounds).
I might make some speed improvments in the future by adding optional pre-compiled rust binaries for PBKDF2 

## Security Warning

⚠️ Handle output carefully - The tool may print your mnemonic, password, and WIF key to console. Use responsibly and avoid testing on large wallets unless necessary.
Note that the cracking speed of this script is rather low, meaning .pin files use strong encryption and are not too easy to hack. Still, it is always advised to use strong password! Note that modern desktop wallets encode the mnemonic bytes directly in the .pin file. The security implication is that it is advised not to reuse this mnemonic for any other purposes!
Secondly, note that the Electrum style bitcoin legacy address is used for the file name. Using the same mnemonic for Verus and a legacy lightning wallet is therefore even more strongly dis-advised. So in short, use common sense, multiple mnemonics for different wallets and strong passwords, just the usual crypto advice.


## Need help?
Reach out on the Verus forum to me or other community members. There are many helpful people out there (do not share your wallet with them!). If you have a real difficult case and are unable to recover your Verus or other crypto, feel free to reach out to me via the contact form on my website.

## License
Apache v2. Free software.

Author: Niels Zondervan, Wallet Recovery NL <br> 
https://www.walletrecovery.nl <br> 
https://verus.io

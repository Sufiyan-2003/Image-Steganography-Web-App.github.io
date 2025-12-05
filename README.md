🔐 Secure LSB Steganography Web App

A powerful and user-friendly web application that allows users to hide and retrieve secret messages inside images using LSB (Least Significant Bit) Steganography, combined with strong AES-level encryption (Fernet) for maximum security.

This project makes digital communication safer by embedding encrypted text inside image pixels — making the hidden data invisible and secure.

🌟 Features
✅ 1. LSB Image Steganography (Encode & Decode)

Hide any text message inside an image using LSB manipulation.

Retrieve hidden secrets seamlessly when the correct password is provided.

🔐 2. Encrypted Message Storage

All messages are:

Encrypted using Fernet (AES-128 CBC + HMAC)

Password-protected

Secure against tampering and brute-force attacks

The message is embedded only after encryption — preventing unauthorized extraction.

📁 3. Password Auto-Generation

If a password is not provided during encoding:

The system automatically generates a strong 16-character secure password

Displayed for the user to copy after encoding

🎨 4. Modern Glass-UI Web Interface

Your frontend includes:

Beautiful neumorphic / frosted-glass UI

Drag-and-drop image uploading

Smooth animations (glow, slide, pulses)

Success/error toast notifications

Responsive design for mobile & desktop

(From index.html) 

index

🖼️ 5. Downloadable Encoded Image

After encoding:

The system produces a new .png image with hidden data

User can download the encoded file instantly

🔍 6. Smart Decoding With Error Handling

Detects message boundaries using a unique delimiter ###END###

Validates password before decrypting

Displays friendly error messages if:

Wrong password

Image not encoded

Data corrupted

🧹 7. Auto-Cleanup Option

A backend maintenance route can clean encoded images older than 24 hours (optional).

🛠️ How It Works (Technical Overview)
1. Message Encryption

Before hiding the message, it is encrypted:

Password → PBKDF2 key derivation → AES-compatible key

Encryption using Fernet cryptography

(from backend logic in app.py) 

app

2. Binary Conversion

Encrypted bytes → binary string → embedded bit-by-bit into image pixel LSB values.

3. LSB Encoding

Each byte of the message replaces one least significant bit across image channels.

4. Decoding

Extract LSB bits back

Reconstruct encrypted message

Detect delimiter

Decrypt using provided password

📂 Project Structure
Secure-Steganography/
│
├── app.py                # Flask backend + encryption + steganography logic
├── index.html            # Modern UI for encoding & decoding
├── encoded_images/       # Auto-generated folder for encoded outputs
├── requirements.txt      # Dependencies
└── README.md             # Project documentation

🚀 Getting Started
1. Install Dependencies

(From requirements.txt) 

requirements

pip install -r requirements.txt


Or manually:

pip install Flask Pillow numpy cryptography

2. Run the Application
python app.py


Server will start at:

http://127.0.0.1:5000/

🎮 How to Use
🔒 Encode a Message

Upload an image (.png, .jpg, .jpeg, .bmp, .tiff)

Enter the secret message

Enter a password (or let the app generate one)

Click Encode Message

Download the new encoded image

🔓 Decode a Message

Upload an encoded image

Enter the correct password

Click Decode Message

The hidden message appears instantly

🔧 Backend Security Highlights
✔ AES-level Fernet encryption
✔ PBKDF2 key derivation
✔ Password-based access control
✔ Embedded end-delimiter for accurate extraction
✔ Validation for corrupted or modified images
🎨 UI Highlights (from frontend)

Floating glass cards

Animated buttons & pulsating highlights

Drag-and-drop file inputs

Real-time loading spinners

Smooth hover & shadow transitions

Auto-styled flash notifications

All built from index.html 

index

🧪 Example Use Cases

Secure message sharing

Hidden watermarking

Protect confidential information

Digital forensics

Cybersecurity demonstrations

College mini-project or major-project

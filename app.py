from flask import Flask, request, render_template, send_file, redirect, url_for, flash
from PIL import Image
import numpy as np
import io
import base64
import os
import secrets
import hashlib
from cryptography.fernet import Fernet
import tempfile
from datetime import datetime

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Needed for flash messages, CSRF, etc.

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp', 'tiff'}

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = 'encoded_images'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

class SecureSteganography:
    @staticmethod
    def _generate_password():
        """Generate a secure random password."""
        return secrets.token_urlsafe(16)
    
    @staticmethod
    def _derive_key(password):
        """Derive encryption key from password."""
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), b'salt_', 100000)
        return base64.urlsafe_b64encode(key)
    
    @staticmethod
    def _encrypt_message(message, password):
        """Encrypt message using Fernet encryption."""
        key = SecureSteganography._derive_key(password)
        f = Fernet(key)
        return f.encrypt(message.encode())
    
    @staticmethod
    def _decrypt_message(encrypted_message, password):
        """Decrypt message using Fernet encryption."""
        key = SecureSteganography._derive_key(password)
        f = Fernet(key)
        return f.decrypt(encrypted_message).decode()
    
    @staticmethod
    def _message_to_binary(message):
        """Convert message to binary string."""
        return ''.join(format(byte, '08b') for byte in message)
    
    @staticmethod
    def _binary_to_message(binary_string):
        """Convert binary string back to message."""
        # Ensure the binary string length is a multiple of 8
        while len(binary_string) % 8 != 0:
            binary_string += '0'
        
        message = bytearray()
        for i in range(0, len(binary_string), 8):
            byte = binary_string[i:i+8]
            message.append(int(byte, 2))
        return bytes(message)
    
    @staticmethod
    def encode_message(image_array, message, password=None):
        """
        Encode a message into an image using LSB steganography with encryption.
        
        Args:
            image_array: numpy array of the image
            message: string message to hide
            password: optional password for encryption (will generate if None)
        
        Returns:
            tuple: (encoded_image_array, password_used)
        """
        if password is None:
            password = SecureSteganography._generate_password()
        
        # Encrypt the message
        encrypted_message = SecureSteganography._encrypt_message(message, password)
        
        # Add delimiter to mark end of message
        encrypted_message_with_delimiter = encrypted_message + b'###END###'
        
        # Convert to binary
        binary_message = SecureSteganography._message_to_binary(encrypted_message_with_delimiter)
        
        # Check if image can hold the message
        image_capacity = image_array.shape[0] * image_array.shape[1] * image_array.shape[2]
        if len(binary_message) > image_capacity:
            raise ValueError("Image is too small to hold the message")
        
        # Flatten the image array for easier manipulation
        flat_image = image_array.flatten()
        
        # Encode the message
        for i, bit in enumerate(binary_message):
            # Modify the least significant bit
            flat_image[i] = (flat_image[i] & 0xFE) | int(bit)
        
        # Reshape back to original dimensions
        encoded_image = flat_image.reshape(image_array.shape)
        
        return encoded_image, password
    
    @staticmethod
    def decode_message(image_array, password):
        """
        Decode a message from an image using LSB steganography with decryption.
        
        Args:
            image_array: numpy array of the encoded image
            password: password for decryption
        
        Returns:
            string: decoded message
        """
        # Flatten the image array
        flat_image = image_array.flatten()
        
        # Extract binary message
        binary_message = ''
        delimiter_binary = SecureSteganography._message_to_binary(b'###END###')
        
        # Extract bits until we find the delimiter or reach the end
        for i in range(len(flat_image)):
            # Extract the least significant bit
            bit = flat_image[i] & 1
            binary_message += str(bit)
            
            # Check if we've found the delimiter
            if binary_message.endswith(delimiter_binary):
                # Remove the delimiter from the binary message
                binary_message = binary_message[:-len(delimiter_binary)]
                break
        
        # Convert binary to encrypted message
        encrypted_message = SecureSteganography._binary_to_message(binary_message)
        
        # Decrypt the message
        try:
            decrypted_message = SecureSteganography._decrypt_message(encrypted_message, password)
            return decrypted_message
        except Exception as e:
            raise ValueError("Invalid password or corrupted data") from e

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route('/encode', methods=['POST'])
def encode():
    try:
        image_file = request.files.get('image')
        message = request.form.get('message', '').strip()
        password = request.form.get('password', '').strip()

        if not image_file or not allowed_file(image_file.filename) or not message:
            flash("Please provide all necessary inputs.")
            return redirect(url_for('index'))
        
        # Open and convert image
        image = Image.open(image_file).convert('RGB')
        image_array = np.array(image)
        
        # Encode the message
        encoded_array, used_password = SecureSteganography.encode_message(
            image_array, message, password if password else None
        )
        
        # Convert back to image
        encoded_image = Image.fromarray(encoded_array)
        
        # Generate unique filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        original_name = os.path.splitext(image_file.filename)[0]
        filename = f"encoded_{original_name}_{timestamp}.png"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        # Save the encoded image to file
        encoded_image.save(filepath, format='PNG')
        
        # Convert to base64 for display
        img_bytes = io.BytesIO()
        encoded_image.save(img_bytes, format='PNG')
        img_bytes.seek(0)
        b64_img = base64.b64encode(img_bytes.getvalue()).decode()
        
        flash("Image encoded successfully! You can now download it.", "success")
        return render_template('index.html', 
                             encoded_image=f"data:image/png;base64,{b64_img}", 
                             password=used_password if not password else None,
                             download_filename=filename)
    
    except Exception as e:
        flash(f"Error encoding message: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route('/decode', methods=['POST'])
def decode():
    try:
        image_file = request.files.get('image')
        password = request.form.get('password', '').strip()
        
        if not image_file or not allowed_file(image_file.filename) or not password:
            flash("Please provide the image and the password.", "error")
            return redirect(url_for('index'))
        
        # Open and convert image
        image = Image.open(image_file).convert('RGB')
        image_array = np.array(image)
        
        # Decode the message
        message = SecureSteganography.decode_message(image_array, password)
        flash("Message decoded successfully!", "success")
        return render_template('index.html', decoded_message=message)
    
    except Exception as e:
        flash(f"Error decoding message: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download_file(filename):
    """Download the encoded image file."""
    try:
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename)
        else:
            flash("File not found.", "error")
            return redirect(url_for('index'))
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", "error")
        return redirect(url_for('index'))

@app.route('/cleanup')
def cleanup_old_files():
    """Clean up old encoded images (optional maintenance endpoint)."""
    try:
        import time
        current_time = time.time()
        files_deleted = 0
        
        for filename in os.listdir(UPLOAD_FOLDER):
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(filepath):
                # Delete files older than 24 hours (86400 seconds)
                file_age = current_time - os.path.getmtime(filepath)
                if file_age > 86400:
                    os.remove(filepath)
                    files_deleted += 1
        
        return f"Cleaned up {files_deleted} old files."
    except Exception as e:
        return f"Error during cleanup: {str(e)}"

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
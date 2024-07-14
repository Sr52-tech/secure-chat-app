from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from flask_socketio import SocketIO, join_room, leave_room, send
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import itertools
import time
import threading

app = Flask(__name__)
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)
attacker_active = False
attacker_target_user = None
intercepted_messages = []

# User data storage (for demo purposes)
users = {}

# Function to hash the password
def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')

# Function to verify the password
def verify_password(stored_password, provided_password):
    return bcrypt.check_password_hash(stored_password, provided_password)

# Function to generate RSA keys
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Function to create a HMAC for the message
def create_hmac(message, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode('utf-8'))
    return h.finalize()

# Function to verify the HMAC of the message
def verify_hmac(message, key, received_hmac):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(message.encode('utf-8'))
    try:
        h.verify(received_hmac)
        return True
    except:
        return False

# Function to encrypt a message using AES
def encrypt_message_aes(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    hmac_value = create_hmac(message, key)
    return iv + hmac_value + encrypted_message

# Function to decrypt a message using AES
def decrypt_message_aes(encrypted_message, key):
    iv = encrypted_message[:16]
    received_hmac = encrypted_message[16:48]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(encrypted_message[48:]) + decryptor.finalize()
    message = decrypted_message.decode('utf-8')
    if verify_hmac(message, key, received_hmac):
        return message
    else:
        raise ValueError("Message integrity check failed")

# Function to securely exchange AES keys using RSA
def exchange_keys(public_key):
    aes_key = os.urandom(32)
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key, encrypted_aes_key

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users:
            flash('Username already exists.')
            return redirect(url_for('register'))
        hashed_password = hash_password(password)
        private_key, public_key = generate_rsa_keys()
        users[username] = {'password': hashed_password, 'private_key': private_key, 'public_key': public_key}
      
        flash('User registered successfully.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username not in users or not verify_password(users[username]['password'], password):
            flash('Invalid username or password.')
            return redirect(url_for('login'))
        session['username'] = username
        return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', username="attacker" if attacker_active else session['username'])

@socketio.on('message')
def handle_message(data):
    username = session.get('username')
    if username:
        private_key = users[username]['private_key']
        public_key = users[username]['public_key']
        aes_key, encrypted_aes_key = exchange_keys(public_key)
        encrypted_message = encrypt_message_aes(data['message'], aes_key)
        
        # Intercept the encrypted message for the attacker to decode later
        intercepted_messages.append({
            'encrypted_message': encrypted_message,
            'aes_key': aes_key,
            'iv': encrypted_message[:16]
        })
        
        decrypted_message = decrypt_message_aes(encrypted_message, aes_key)
        # Send the encrypted message to all clients in the room
        send({'username': username, 'message': decrypted_message}, room=data['room'])

@socketio.on('join')
def on_join(data):
    username = session.get('username')
    room = data['room']
    join_room(room)
    send({'message': f'{username} has entered the room.'}, room=room)
    
@socketio.on('leave')
def on_leave(data):
    username = session.get('username')
    room = data['room']
    leave_room(room)
    send({'message': f'{username} has left the room.'}, room=room)

# Function to simulate an attacker using brute force on passwords
def brute_force_attack():
    global attacker_active, attacker_target_user
    characters = 'abcdefghijklmnopqrstuvwxyz0123456789'
    weak_passwords = [''.join(p) for p in itertools.product(characters, repeat=3)]
    
    for username, user_data in users.items():
        for password in weak_passwords:
            if verify_password(user_data['password'], password):
                print(f"Attacker cracked password for user '{username}': {password}")
                attacker_active = True
                attacker_target_user = username
                return
            time.sleep(0.01)

# Function to simulate an attacker using brute force on intercepted messages
def brute_force_decrypt_intercepted_messages():
    if intercepted_messages and attacker_active:
    
        private_key = users[attacker_target_user]['private_key']
        for intercepted in intercepted_messages:
            encrypted_message = intercepted['encrypted_message']
            try:
                decrypted_message = decrypt_message_aes(encrypted_message, intercepted['aes_key'])
                print("😎😎😎😎😎😎😎😎😎")
                print(f"Attacker decrypted message: {decrypted_message}")
                print()
            except Exception as e:
                print(f"Unable to decode the message: {e}")

@app.route("/decrypt")
def intercp():
    brute_force_attack()
    brute_force_decrypt_intercepted_messages()
    return redirect(url_for('chat'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000, ssl_context='adhoc')

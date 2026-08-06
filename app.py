from io import BytesIO
from pathlib import Path

from flask import Flask, render_template, request, send_file, flash
from werkzeug.utils import secure_filename

from encryption import encrypt_data

app = Flask(__name__)
app.secret_key = "replace-with-a-secure-secret"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024


# Home
@app.route('/')
def index():
    return render_template('index.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Encryption
@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        password = (request.form.get('password') or '').strip()

        if not uploaded_file or not uploaded_file.filename:
            flash('Please choose a file to encrypt.')
            return render_template('encrypt.html')

        if not password:
            flash('Please enter a passphrase.')
            return render_template('encrypt.html')

        file_bytes = uploaded_file.read()
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            flash('The file you uploaded exceeds the 100MB limit.')
            return render_template('encrypt.html')

        try:
            encrypted_bytes = encrypt_data(password, file_bytes)
        except Exception as exc:
            flash(f'Encryption failed: {exc}')
            return render_template('encrypt.html')

        original_name = secure_filename(uploaded_file.filename)
        output_name = f"{Path(original_name).stem}.vigilock"
        return send_file(
            BytesIO(encrypted_bytes),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=output_name,
        )

    return render_template('encrypt.html')


# Decryption
@app.route('/decrypt')
def decrypt():
    return render_template('decrypt.html')


# Recovery
@app.route('/recovery')
def recovery():
    return render_template('recovery.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
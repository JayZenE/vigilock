from io import BytesIO
from pathlib import Path

from cryptography.exceptions import InvalidTag
from flask import Flask, render_template, request, send_file, flash
from werkzeug.utils import secure_filename

from encryption import decrypt_data, encrypt_data, recover_key

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
        recovery_phrase = (request.form.get('recovery_phrase') or '').strip()

        if not uploaded_file or not uploaded_file.filename:
            flash('Please choose a file to encrypt.')
            return render_template('encrypt.html')

        if not password:
            flash('Please enter a passphrase.')
            return render_template('encrypt.html')

        if not recovery_phrase:
            flash('Please create a recovery phrase.')
            return render_template('encrypt.html')

        file_bytes = uploaded_file.read()
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            flash('The file you uploaded exceeds the 100MB limit.')
            return render_template('encrypt.html')

        try:
            encrypted_bytes = encrypt_data(
                password,
                file_bytes,
                uploaded_file.filename,
                recovery_phrase,
            )
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
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        password = (request.form.get('password') or '').strip()
        recovery_phrase = (request.form.get('recovery_phrase') or '').strip()

        if not uploaded_file or not uploaded_file.filename:
            flash('Please choose a file to decrypt.')
            return render_template('decrypt.html')

        if not password and not recovery_phrase:
            flash('Please enter your password or recovery phrase.')
            return render_template('decrypt.html')

        file_bytes = uploaded_file.read()
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            flash('The file you uploaded exceeds the 100MB limit.')
            return render_template('decrypt.html')

        try:
            credentials = tuple(value for value in (password, recovery_phrase) if value)
            decrypted_bytes, original_name = decrypt_data(credentials, file_bytes)
        except InvalidTag:
            flash('Decryption failed: inputted password is incorrect.')
            return render_template('decrypt.html')
        except Exception as exc:
            flash(f'Decryption failed: {exc}')
            return render_template('decrypt.html')

        if original_name:
            output_name = secure_filename(original_name)
        else:
            output_name = f"{Path(uploaded_file.filename).stem}.decrypted"
        return send_file(
            BytesIO(decrypted_bytes),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=output_name,
        )

    return render_template('decrypt.html')


# Recovery
@app.route('/recovery', methods=['GET', 'POST'])
def recovery():
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        recovery_phrase = (request.form.get('recovery_phrase') or '').strip()

        if not uploaded_file or not uploaded_file.filename:
            flash('Please choose an encrypted file to recover.')
            return render_template('recovery.html')

        if not recovery_phrase:
            flash('Please enter your recovery phrase.')
            return render_template('recovery.html')

        file_bytes = uploaded_file.read()
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            flash('The file you uploaded exceeds the 100MB limit.')
            return render_template('recovery.html')

        try:
            recovered_key = recover_key(recovery_phrase)
            recovered_bytes, original_name = decrypt_data(recovered_key, file_bytes)
        except InvalidTag:
            flash('Recovery failed: the recovery phrase is incorrect.')
            return render_template('recovery.html')
        except Exception as exc:
            flash(f'Recovery failed: {exc}')
            return render_template('recovery.html')

        output_name = secure_filename(original_name) if original_name else f'{Path(uploaded_file.filename).stem}.recovered'
        return send_file(
            BytesIO(recovered_bytes),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=output_name,
        )

    return render_template('recovery.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
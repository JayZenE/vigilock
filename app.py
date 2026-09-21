from io import BytesIO
from pathlib import Path
import sys

from cryptography.exceptions import InvalidTag
from flask import Flask, render_template, request, send_file, flash
from werkzeug.utils import secure_filename

from encryption import decrypt_password_data, decrypt_recovery_data, encrypt_data, recover_key

BASE_DIR = Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / 'templates'),
    static_folder=str(BASE_DIR / 'static'),
)
app.secret_key = "replace-with-a-secure-secret"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024
RECOVERY_QUESTIONS = [
    ('first_pet', 'What was the name of your first pet?'),
    ('birth_city', 'In what city were you born?'),
    ('favorite_teacher', 'What was the name of your favorite teacher?'),
    ('childhood_street', 'What street did you grow up on?'),
    ('favorite_book', 'What was your favorite book as a child?'),
    ('first_concert', 'What was the first concert you attended?'),
]
RECOVERY_QUESTION_IDS = {question_id for question_id, _ in RECOVERY_QUESTIONS}


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
        recovery_question = request.form.get('recovery_question') or ''
        recovery_answer = (request.form.get('recovery_answer') or '').strip()

        if not uploaded_file or not uploaded_file.filename:
            flash('Please choose a file to encrypt.')
            return render_template('encrypt.html', recovery_questions=RECOVERY_QUESTIONS)

        if not password:
            flash('Please enter a passphrase.')
            return render_template('encrypt.html', recovery_questions=RECOVERY_QUESTIONS)

        if recovery_question not in RECOVERY_QUESTION_IDS:
            flash('Please choose a recovery question.')
            return render_template('encrypt.html', recovery_questions=RECOVERY_QUESTIONS)

        if not recovery_answer:
            flash('Please enter an answer to your recovery question.')
            return render_template('encrypt.html', recovery_questions=RECOVERY_QUESTIONS)

        file_bytes = uploaded_file.read()
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            flash('The file you uploaded exceeds the 100MB limit.')
            return render_template('encrypt.html', recovery_questions=RECOVERY_QUESTIONS)

        try:
            encrypted_bytes = encrypt_data(
                password,
                file_bytes,
                uploaded_file.filename,
                recovery_answer,
                recovery_question=recovery_question,
            )
        except Exception as exc:
            flash(f'Encryption failed: {exc}')
            return render_template('encrypt.html', recovery_questions=RECOVERY_QUESTIONS)

        original_name = secure_filename(uploaded_file.filename)
        output_name = f"{Path(original_name).stem}.vigilock"
        return send_file(
            BytesIO(encrypted_bytes),
            mimetype='application/octet-stream',
            as_attachment=True,
            download_name=output_name,
        )

    return render_template('encrypt.html', recovery_questions=RECOVERY_QUESTIONS)


# Decryption
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        password = (request.form.get('password') or '').strip()

        if not uploaded_file or not uploaded_file.filename:
            flash('Please choose a file to decrypt.')
            return render_template('decrypt.html')

        if not password:
            flash('Please enter your password.')
            return render_template('decrypt.html')

        file_bytes = uploaded_file.read()
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            flash('The file you uploaded exceeds the 100MB limit.')
            return render_template('decrypt.html')

        try:
            decrypted_bytes, original_name = decrypt_password_data(password, file_bytes)
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
        recovery_question = request.form.get('recovery_question') or ''
        recovery_answer = (request.form.get('recovery_answer') or '').strip()

        if not uploaded_file or not uploaded_file.filename:
            flash('Please choose an encrypted file to recover.')
            return render_template('recovery.html')

        if recovery_question not in RECOVERY_QUESTION_IDS:
            flash('Please choose the recovery question used during encryption.')
            return render_template('recovery.html', recovery_questions=RECOVERY_QUESTIONS)

        if not recovery_answer:
            flash('Please enter the answer to your recovery question.')
            return render_template('recovery.html', recovery_questions=RECOVERY_QUESTIONS)

        file_bytes = uploaded_file.read()
        if len(file_bytes) > MAX_UPLOAD_BYTES:
            flash('The file you uploaded exceeds the 100MB limit.')
            return render_template('recovery.html')

        try:
            recovered_key = recover_key(recovery_answer)
            recovered_bytes, original_name = decrypt_recovery_data(
                recovered_key, file_bytes, recovery_question
            )
        except InvalidTag:
            flash('Recovery failed: the recovery phrase is incorrect.')
            return render_template('recovery.html', recovery_questions=RECOVERY_QUESTIONS)
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

    return render_template('recovery.html', recovery_questions=RECOVERY_QUESTIONS)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

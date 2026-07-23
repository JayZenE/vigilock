from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "replace-with-a-secure-secret"


# Home
@app.route('/')
def index():
    return render_template('index.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Encryption
@app.route('/encrypt')
def encrypt():
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
    app.run(debug=True)
# Vigilock

A simple Flask-based file encryption and recovery utility.

## Structure

- `app.py`: Flask application entry point
- `static/`: CSS, JS, images, and uploads
- `templates/`: HTML templates
- `encryption/`: encryption, decryption, and recovery modules
- `docs/`: project documentation and design artifacts

## Running the portable Windows build

Copy `release/vigilock.exe` to the other Windows computer and double-click it. VigiLock starts a local Flask server and opens the default web browser automatically. Keep the executable running while using the site; close it when finished.

## Running from source

Install the dependencies from `requirements.txt`, then run `desktop.py`. It starts Flask on a local port and opens the default browser.

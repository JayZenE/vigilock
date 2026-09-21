import threading
import webbrowser
from werkzeug.serving import make_server

from app import app


class FlaskServer(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.server = make_server('127.0.0.1', 0, app)
        self.port = self.server.server_port

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()


def main():
    server = FlaskServer()
    server.start()
    url = f'http://127.0.0.1:{server.port}'
    webbrowser.open(url)
    try:
        server.join()
    finally:
        server.stop()


if __name__ == '__main__':
    main()

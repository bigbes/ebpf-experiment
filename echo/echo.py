from http.server import HTTPServer, BaseHTTPRequestHandler
# from ssl import SSLContext, CERT_REQUIRED, PROTOCOL_TLS_SERVER
import ssl


class EchoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)

    def do_POST(self):
        request_path = self.path

        length = int(self.headers.get('content-length', '0'))
        self.wfile.write(self.rfile.read(length))
        self.send_response(200)

    do_PUT = do_POST
    do_DELETE = do_GET

def __main__():
    # Generate self-signed SSL certificate (for testing purposes)
    # openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
    certfile = "./server.pem"

    # context = SSLContext(protocol=PROTOCOL_TLS_SERVER)
    # context.verify_mode = CERT_REQUIRED
    # context.load_verify_locations("./server.pem")

    # Set up the server
    httpd = HTTPServer(('localhost', 8443), EchoHandler)
    # httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.socket = ssl.wrap_socket(httpd.socket, keyfile=certfile, certfile=certfile, server_side=True)

    # Start the server
    print("Python HTTPS echo server running on https://localhost:8443/")
    httpd.serve_forever()

if __name__ == "__main__":
    __main__()

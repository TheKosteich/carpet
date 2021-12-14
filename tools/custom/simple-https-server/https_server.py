import http.server
import ssl

"""
Generate certificate with openssl:
    openssl req -new -x509 -keyout server.pem -out server.pem -day 1825 -nodes
"""
server_address = ('localhost', 443)
httpd = http.server.HTTPServer(server_address,
                               http.server.SimpleHTTPRequestHandler)
httpd.socket = ssl.wrap_socket(httpd.socket,
                               server_side=True,
                               certfile='server.pem',
                               ssl_version=ssl.PROTOCOL_TLS)
try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print('*' * 49)
    print("*** Simple Python HTTPS Server say's goodbye!!! ***")
    print('*' * 51)

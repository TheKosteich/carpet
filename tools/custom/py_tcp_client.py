import socket

target_host = 'python.org'
target_port = 80

# some another example
# target_host = '127.0.0.1'
# target_port = 9998

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect the client
client.connect((target_host, target_port))
# send some data
client.send(b'GET / HTTP/1.1\r\nHost: python.org\r\n\r\n')
# some another example
# client.send(b'ABC')
# receive some data
response = client.recv(4096)
print(response.decode())

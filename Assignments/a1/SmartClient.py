'''
	CSC361 - Assignment 1
	Devroop Banerjee
	V00837868
'''

import sys
import socket
import ssl


host = sys.argv[1]
HTTP_ort = 80
HTTP_ort_S = 443


suck_et = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
ssl_sock = context.wrap_socket(suck_et, server_hostname=host)


try:
	ssl_sock.connect((host, HTTP_ort_S))
except suck_et.error as err:
	print(str(e))


REQUEST = "GET / HTTP/1.1\r\n\r\nHost: {}\r\n\r\n".format(host)
ssl_sock.send(REQUEST.encode())
result = ssl_sock.recv(20480)


print("\n---Request begin---")
print(REQUEST)
print("---Request end---\nHTTP request sent, awaiting response...\n\n---Response header---")
print(result)
print('\nwebsite: ' + host)



#Ran out of time before I could correct the following error ==> "TypeError: 'str' does not support the buffer interface". Hence I commented the code below.
'''
if '2**' in result:
	print('\n1. Support for HTTPS: yes')
else:
	print('\n1. Support for HTTPS: no')
'''


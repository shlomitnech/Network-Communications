# client.py
# Shlomit Volpin
# 550618034
import socket
import select
import msvcrt
import sys
import protocol

# EXIT will close client
def EXIT():
    print("\n" + protocol.GOODBYE)
    my_socket.close()

my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_socket.connect(("127.0.0.1", 5555))
my_socket.setblocking(0)

print("Please enter commands\n")
msg = ""
while msg != "EXIT": #must put a space after Exit
    rlist, wlist, xlist = select.select([my_socket], [], [], 0.1)
    for s in rlist:
        server_msg = s.recv(protocol.MAX_MSG_LENGTH).decode()
        print(server_msg)
        if server_msg == "":
            print('Closing Server')
            s.close()
    if msvcrt.kbhit():
        key = msvcrt.getche().decode()
        if key != '\r':
            msg += key
        else:
            protocol.MSG(msg, my_socket) #send the message
            print(msg)
            msg = ''

# close the client
EXIT()
#Shlomit Volpin
#550618034
import socket
import select
import protocol

#read the message and respond
def handle_client_request(current_socket, data, clients_names, client_sockets):
    print(data)
    data = data.split(" ")
    dest_socket = current_socket
    if current_socket not in clients_names.values(): #hasn't yet put in Name
        if data[0] == "NAME":
            client_name = ' '.join(data[1:])
            if client_name in clients_names: # client chose a name already there
                reply = protocol.NAME_EXISTS_ERROR
            elif client_name.isalpha(): #check that it is all letters and one word
                clients_names[client_name] = current_socket #add the name to the socket
                reply = "HELLO " + client_name
            else:
                reply = protocol.INCORRECT_SYNTAX
        else:
            reply = protocol.NO_NAME
    # send all the client names currently connected to the current socket
    elif data[0] == "GET_NAMES":
        reply = protocol.GET_NAMES(clients_names)
    #send a message from client to client
    elif data[0] == "MSG":
        reply, dest_socket = protocol.SEND_MESSAGE(current_socket, data[1], data[2], clients_names, client_sockets)
    elif data[0] == "NAME":
        reply = protocol.ALREADY_NAMED
    else:
        reply = protocol.INCORRECT_SYNTAX

    reply = "Server Sent: " + reply
    return reply, dest_socket

# to print all the names
def print_client_sockets(client_names):
    for c in client_names:
        print("\t", c.getpeername())

# to remove the client from the list
def handle_client_disconnect(disconnected_socket, clients_names, client_sockets):
    for entry, socket in clients_names.items():
        if socket == disconnected_socket:
            sender_name = entry
            clients_names.pop(sender_name)
            client_sockets.remove(disconnected_socket)
            disconnected_socket.close()
            break


def main():
    print("Setting up server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((protocol.SERVER_IP, protocol.SERVER_PORT))
    server_socket.listen()
    server_socket.setblocking(0)  # Set non-blocking mode for server socket
    print("Listening for clients...")
    client_sockets = []
    messages_to_send = []
    clients_names = {}
    while True:
        try:
            read_list = client_sockets + [server_socket]
            ready_to_read, ready_to_write, in_error = select.select(read_list, client_sockets, [])
            for current_socket in ready_to_read:
                if current_socket is server_socket:
                    client_socket, client_address = server_socket.accept()
                    print("New client joined!\n", client_address)
                    client_socket.setblocking(0)  # Set non-blocking mode for client socket
                    client_sockets.append(client_socket)
                    print_client_sockets(client_sockets)
                else:
                    try:
                        print("New data from client\n")
                        data = current_socket.recv(protocol.MAX_MSG_LENGTH).decode()
                        if not data:
                            print("Connection closed\n")
                            handle_client_disconnect(current_socket, clients_names, client_sockets)
                    except ConnectionResetError:
                        print("Connection reset by client\n")
                        handle_client_disconnect(current_socket, clients_names, client_sockets)
                        continue
                    response, dest_socket = handle_client_request(current_socket,data, clients_names, client_sockets)
                    protocol.MSG(response,dest_socket)

            # write to everyone
            for message in messages_to_send:
                current_socket, data = message
                if current_socket in ready_to_write:
                    current_socket.send(data[1].encode())
                    messages_to_send.remove(message)
                    if data == "":
                        current_socket.close()
        except Exception as e:
            print("ERROR: SOMETHING IS WRONG")


if __name__ == '__main__':
    main()

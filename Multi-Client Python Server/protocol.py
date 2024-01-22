#Shlomit Volpin
#550618034
#protocol
import select

NAME_EXISTS_ERROR = "ERROR: Name already exists"
INCORRECT_SYNTAX = "ERROR: Incorrect Message"
ERROR_SENDING = "ERROR: That user does not exist"
ALREADY_NAMED = "ERROR: You already have a NAME"
NO_NAME = "ERROR: You don't have a NAME"
GOODBYE = "GOODBYE"
HEADER = 64
MAX_MSG_LENGTH = 1024
SERVER_PORT = 5555
SERVER_IP = "0.0.0.0"
FORMAT = 'utf-8'

# when one client wanted to send a message to another
def SEND_MESSAGE(current_socket, dest_name, message, clients_names, client_sockets):
    sender = [k for k, v in clients_names.items() if v == current_socket][0]
    if dest_name not in clients_names: #see if the name is on the server
        reply = ERROR_SENDING
        dest_socket = current_socket
    else:
        ready_read, ready_write, ex = select.select([], client_sockets, [])
        if clients_names[dest_name] in ready_write:
            reply = str(sender) + " sent " + message
            dest_socket = clients_names[dest_name]
        else:
            reply = ERROR_SENDING

    return reply, dest_socket

# when client wanted to see all the client names
def GET_NAMES(clients_names):
    client_names_list = list(clients_names.keys())
    if client_names_list:
        return ' '.join(client_names_list)
    else:  # no clients sent a name
        return "ERROR: No names registered"


# Send a message to the server (with the appropriate byte size)
def MSG(msg, destination):
    message = msg.encode(FORMAT)
    send_len = str(len(message)).encode(FORMAT)
    send_len += b' ' * (MAX_MSG_LENGTH - len(send_len))
    destination.send(message)
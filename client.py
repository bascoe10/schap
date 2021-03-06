import argparse
import socket
import random
import rsa
import threading
import sys

SERVER = []
KEYPAIR = []
MESSAGE_SESSIONS = {} #holds a list of users that are currently chatting with

# allows user to enter the command to send
def raw_command():
    sock = connect_to_server()
    message = raw_input("Enter command with args> ")
    message = "{0}\r\n".format(message)
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    print resp_code + ' ' + resp_message

#handles removing a user from the server
def delete_user():
    sock = connect_to_server()
    message = raw_input("Enter username> ")
    message = "DELETEUSER {0}\r\n".format(message)
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    print resp_message

#handles terminating a user's session
def terminate_a_session():
    sock = connect_to_server()
    message = raw_input("Enter username> ")
    message = "KICK {0}\r\n".format(message)
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    print resp_message

#handles broadcasting a message
def broadcast_message():
    sock = connect_to_server()
    message = raw_input("Enter message> ")
    message = "BROADCAST {0}\r\n".format(message)
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    print resp_message

#handles adding a user to list of admins
def add_admin():
    sock = connect_to_server()
    user = raw_input("Enter username> ")
    message = "ADDADMIN {0}\r\n".format(user)
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    print resp_message

#handles moving from the ADMIN state to CONN EST state
def admin_exit():
    sock = connect_to_server()
    message = "EXIT\r\n"
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    print resp_message

#handles moving to the ADMIN state
def admin_mode():
    sock = connect_to_server()
    message = "ADMIN\r\n"
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    print resp_message

#handles sending encryption ket to server
def push_key():
    sock = connect_to_server()
    message = "KEY {0}\r\n".format(KEYPAIR[0].save_pkcs1())
    sock.send(message)
    code, message = read_message(sock)
    print message
    return

def send_encrypted_message():
    user = raw_input("Enter username: ")
    #get public key
    sock = connect_to_server()
    message = "LKUP {0}\r\n".format(user)
    sock.send(message)
    code, message = read_message(sock)
    if code != '000':
        print "Cannot retrieve key"
        return
    pem_file = message.split('#', 1)[1]
    if len(pem_file) == 0:
        print 'No key found for user please send unencrypted message'
        return

    key = rsa.PublicKey.load_pkcs1(pem_file)

    user_session = MESSAGE_SESSIONS.get(user) #check is user is in active list
    if not user_session: # if they are not then add them
        user_session = {
            'message_id': random.randint(1,65536),
            'message_2_ack': []
        }
        MESSAGE_SESSIONS[user] = user_session

    message = raw_input("Enter message: ")
    message = message.encode('utf8')
    crypt = str(rsa.encrypt(message, key))
    sock = connect_to_server()
    message = "ENCRYPTMSG {0}#{1}#{2} {3}\r\n".format(user, user_session['message_id'], "", crypt)
    sock.send(message)
    code, message = read_message(sock)
    print message
    user_session['message_id'] = user_session['message_id'] + 1
    MESSAGE_SESSIONS[user] = user_session

def send_message():
    user = raw_input("Enter username: ")
    user_session = MESSAGE_SESSIONS.get(user) #check is user is in active list
    if not user_session: # if they are not then add them
        user_session = {
            'message_id': random.randint(1,65536),
            'message_2_ack': []
        }

    message = raw_input("Enter message: ")
    message = "SENDMSR {0}#{1}#{2} {3}\r\n".format(user, user_session['message_id'], "", message)
    # print message
    sock = connect_to_server()
    sock.send(message)
    code, message = read_message(sock)
    print message
    user_session['message_id'] = user_session['message_id'] + 1
    user_session['message_2_ack'].append(user_session['message_id'])
    MESSAGE_SESSIONS[user] = user_session

#handles loggin out
def logout():
    sock = connect_to_server()
    message = "QUIT\r\n"
    sock.send(message)
    response = read_message(sock)
    print response[1]

# handles checking a server version
def check_server_version():
    sock = connect_to_server()
    message = "VERSION\r\n"
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    print 'Server version = ' + resp_message

#handles pinging the server
def ping_server():
    sock = connect_to_server()
    message = "PING\r\n"
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    print resp_message

#handles looking up a user from the server
def lookup_user():
    username = raw_input("Enter username: ")
    sock = connect_to_server()
    message = "LKUP {0}\r\n".format(username)
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    if resp_code == '000': #check if query was successful
        name, key = resp_message.split('#') # separate username from key
        print "User".center(40, '-')
        print "Name: " + name
        print "Key: \n" + key
        print "-" * 40
    else:
        resp_message

#handles listing all users connected to the server
def list_users():
    sock = connect_to_server()
    message = "LIST\r\n"
    sock.send(message)
    resp_code, resp_message = read_message(sock)
    if resp_code == '000':
        print "List of users".center(40, '-')
        print '\n'.join(resp_message.split(','))
        print "-" * 40
    else:
        print resp_message

# helper method to connect to server
def connect_to_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(SERVER[0])
    return sock

'''
Main Menu
list out the Main menu of the client application
'''
def menu():
    print("\n")
    print('Main Menu'.center(40, '*'))
    print("List of commands")
    print("[ 1] List connect users")
    print("[ 2] Lookup user")
    print("[ 3] Ping server")
    print("[ 4] Check server version")
    print("[ 5] Send message")
    print("[ 6] Send Encrypted Message")
    print('[ 7] Generate encryption key')
    print('[ 8] Enter ADMIN mode')
    print('[ 9] Create new admin [ADMIN]')
    print('[10] Broadcast message [ADMIN]')
    print('[11] Terminate a user session [ADMIN]')
    print('[12] Delete user [ADMIN]')
    print("[13] Exit Admin Mode")
    print("[14] Help")
    print("[15] Command mode")
    print("[16] Quit")

#helper method for reading message from socket
#read from the socket until the delimeter
def read_message(sock):
    message = ""
    while not message.endswith('\r\n'):
        message = message + sock.recv(1024)
    message = message.rstrip('\r\n')
    return message.split(' ', 1)

#run the user through the login sequence with the server,
#response codes are check to make sure the correct commands are sent to the server
#this method returns false if the login sequence fails
def welcome_sequence():
    sock = connect_to_server()
    sock.send("VERSION\r\n") #first message sent to determine the version of the server
    resp_code, resp_message = read_message(sock)
    if resp_code == '001' or resp_code == '000':
        print 'Server version = ' + resp_message
    else:
        print 'Cannot determine the Server version'
        return False

    #since server version was determined the next message the server is expecting is a USER message
    username = raw_input("Enter username: ")
    message = "USER {0}\r\n".format(username)

    # message = "USER abass\r\n"
    sock.send(message)
    response_code, response_message = read_message(sock)
    print response_message # print corresponding message
    #-001 is returned if the registration is required
    #-000 is return if the user exists
    if response_code == '000' or response_code == '001':
        password = raw_input("Enter password: ")
        message = "PASS {0}\r\n".format(password)
        # message = "PASS abass\r\n"
        sock.send(message)
        response_code, response_message = read_message(sock)
        print response_message
        if response_code == '000':
            #establish a port for the server to send command messages
            message = "PORT {0}\r\n".format(SERVER[1])
            # message = "PORT 1045\r\n"
            sock.send(message)
            code, message = read_message(sock)
            print message
            if code != '000':
                return False
            user_input = raw_input('Do you want to set encryption key [y]/[n]\n>')
            user_input = user_input.lower()
            if user_input == 'y' or user_input == 'yes':
                push_key()
            return True
    # user message is 100 user is already signed
    elif response_code == '100':
        port = raw_input("Enter port: ")
        message = "PORT {0}\r\n".format(SERVER[1])
        # message = "PORT 1045\r\n"
        sock.send(message)
        code, message = read_message(sock)
        print message
        if code != '000':
            return False
        if user_input == 'y' or user_input == 'yes':
            push_key()
        return True

    return False

#handle command messages from the server that are not Implemented in the client
def not_implemented(sock, args):
    print 'Not Implemented'
    sock.send('001 Not Implemented\r\n')

#handle PING command messages from the server
def ping(sock, args):
    sock.send('000 Pong\r\n')

#handle CONFMSG command messages from the server
def confmsg(sock, args):
    if args[0]:
        sock.send('000 Message recieved')
        sender = args[0]
        # header, body = args[1].split(" ", 1)
        print "{0} confirmed message: {1}".format(sender, args[1].split(' ')[1])
    else:
        sock.send('001 No sender included')

#handle SENDMSR command messages from the server
def sendmsr(sock, args):
    if args[0]:
        sock.send('000 Message recieved')
        sender = args[0]
        header, body = args[1].split(" ", 1)
        print "From {0}: {1}".format(sender, body)
        _sock = connect_to_server()
        message = "CONFMSG {0} {1}\r\n".format(sender.lstrip('#'), header.split('#')[1])
        _sock.send(message)
        code, message = read_message(_sock)
        print message
    else:
        sock.send('001 No sender included')

#handle ENCRYPTMSG command messages from the server
def encryptmsg(sock, args):
    if args[0]:
        sock.send('000 Message recieved')
        decrypted_msg = rsa.decrypt(args[1].split(" ", 1)[1].rstrip('\r\n'), KEYPAIR[1])
        print "From {0}: {1}".format(args[0], decrypted_msg)
    else:
        sock.send('001 No sender included')

#handle BROADCAST command messages from the server
def broadcast(sock, args):
    if args[0]:
        sock.send('000 Message recieved')
        print "From {0}: {1}".format(args[0], args[1])
    else:
        sock.send('001 No sender included')


# runs within the thread the receives command message from the server
def recieving_message():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', SERVER[1]))
    except:
        print 'Error establishing listening port please restart'
        return

    while True:
        sock.listen(1) #listens on the predefined port 9876 for server connection
        s_sock, s_address = sock.accept()
        response = ""
        while not response.endswith('\r\n'): #reads from the socket until the delimeter
            response = response + s_sock.recv(1024)

        response = response.rstrip('\r\n') #remove delimeter from recieved message

        sender, command, args = None, None, None

        # if message starts with # extract the sender name
        if response.startswith('#'):
            sender, command, args = response.split(" ", 2)
        else:
            try:
                command, args = response.split(" ", 1)
            except ValueError: #error thrown if their is no argument is passed
                command = response

        #if command is a QUIT respond and then break from listening loop
        if command == 'QUIT':
            print 'closing'
            s_sock.send('000 Closing connection\r\n')
            sock.close()
            break

        #get function corresponding to the command passed or default function
        func = getattr(__import__(__name__), command.lower(), not_implemented)
        func(s_sock, [sender, args])


#User Interface
def client_repl():
    #connection is active if the welcome_sequence return True
    connection_active = welcome_sequence()
    # if active start up the thread for recieving messages
    if connection_active:
        r_thread = threading.Thread(target=recieving_message)
        r_thread.start()
    else:
        print 'Authentication failed'
        return

    menu()
    while connection_active:
        # get user option for the menu
        user_input = raw_input('> ')
        try:
            user_input = int(user_input)
            if user_input == 1:
                list_users()
            elif user_input == 2:
                lookup_user()
            elif user_input == 3:
                ping_server()
            elif user_input == 4:
                check_server_version()
            elif user_input == 5:
                send_message()
            elif user_input == 6:
                send_encrypted_message()
            elif user_input == 7:
                push_key()
            elif user_input == 8:
                admin_mode()
            elif user_input == 9:
                add_admin()
            elif user_input == 10:
                broadcast_message()
            elif user_input == 11:
                terminate_a_session()
            elif user_input == 12:
                delete_user()
            elif user_input == 13:
                admin_exit()
            elif user_input == 14:
                menu()
            elif user_input == 15:
                raw_command()
            elif user_input == 16:
                print 'Good bye!'.center(40, '*')
                if connection_active:
                    logout()
                connection_active = False
            else:
                print 'Please select a valid option. Press [13] for help'
        except ValueError:
            print 'Value has to be an integer'

    return

# helper method for checking connectivity to default or passed port
def check_connectivity(address, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        sock.connect((address, port))
        return True
    except Exception as e:
        return False

#loop through an address space
def address_space_loop(address_space, port):
    address = None
    found = False
    for i in range(0, 256): #loop from 0 to 255
        address = '.'.join(address_space)+'.'+str(i)
        if check_connectivity(address, port):
            print 'Server found.'
            found = True
            break
    if found:
        return address


def check_local_interface(port):
    return check_connectivity('', port)

#method for discovering server on the network
def discover_server(port):
    print 'Finding server...'
    #check if server is running on the same computer as the client
    if check_local_interface(port):
        return ''
    else:
        # return proper IP address for mac but returns loopback address for Linux
        address_space = socket.gethostbyname(socket.gethostname())
        address_space = address_space.split('.')
        address = address_space_loop(address_space[:3], port)
        if address:
            return address

        #Most Linux distros return the L0 address- walkaround
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(('8.8.8.8', 1))
        address_space = sock.getsockname()[0]
        address_space = address_space.split('.')
        address = address_space_loop(address_space[:3], port)
        if address:
            return address
    print 'Server not found'


# using argparse module process the command line arguments
def get_cli_args():
    parser = argparse.ArgumentParser(description='SChaP Client')
    parser.add_argument('--server', metavar='Server port', type=int, default=6789, help='This is the port of the SChaP server is listening on')
    parser.add_argument('--client', metavar='Client port', type=int, default=9876, help='This is the port of the SChaP client is listening on')
    parser.add_argument('--host', metavar='Hostname', type=str, default='', help='This is the hostname of the SChaP server')


    args = parser.parse_args()
    # print args
    host = args.host
    if args.host == '': # only do server discovery if the hostname is not passed
        host = discover_server(args.server)


    # check the validity of the hostname passed in the process convert the host name to ip addr
    try:
        host = socket.gethostbyname(host)
    except:
        print 'Hostname cannot be resolved'
        exit(1)
    return {'host': host, 'server': args.server, 'client': args.client}


def main():
    args = get_cli_args()
    #SERVER object holds need arguments about the server and the port number of the client
    SERVER.append((args['host'], args['server']))
    SERVER.append(args['client'])
    #new rsa key is generated when the application is started and is added to the KEYPAIR obj
    (pubkey, privkey) = rsa.newkeys(512)
    KEYPAIR.append(pubkey)
    KEYPAIR.append(privkey)
    client_repl()
    # threading.Thread(target=client_repl).start()

if __name__ == '__main__':
    main()

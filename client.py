import argparse
import socket
import random
import rsa
import threading

SERVER = []
KEYPAIR = []
MESSAGE_SESSIONS = {} #holds a list of users that are currently chatting with

def gen_key():
    sock = connect_to_server()
    message = "KEY {0}\r\n".format(KEYPAIR[0].save_pkcs1())
    sock.send(message)
    response = sock.recv(1024)
    print response
    return

def send_encrypted_message():
    user = raw_input("Enter username: ")
    #get public key
    sock = connect_to_server()
    message = "LKUP {0}\r\n".format(user)
    sock.send(message)
    response = sock.recv(1024)
    print response
    code, message =  response.split(" ", 1)
    print code
    if code != '000':
        print "Cannot retrieve key"
        return

    key = rsa.PublicKey.load_pkcs1(message.split('#', 1)[1])

    user_session = MESSAGE_SESSIONS.get(user) #check is user is in active list
    if not user_session: # if they are not then add them
        user_session = {
            'message_id': random.randint(1,65536),
            'message_2_ack': []
        }
        MESSAGE_SESSIONS[user] = user_session

    message = "Hello" #raw_input("Enter message: ")
    message = message.encode('utf8')
    crypt = str(rsa.encrypt(message, key))
    sock = connect_to_server()
    message = "ENCRYPTMSG {0}#{1}#{2} {3}\r\n".format(user, user_session['message_id'], "", crypt)
    print message
    sock.send(message)
    response = sock.recv(1024)
    print response
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
        MESSAGE_SESSIONS[user] = user_session

    message = "Hello" #raw_input("Enter message: ")
    sock = connect_to_server()
    message = "SENDMSR {0}#{1}#{2} {3}\r\n".format(user, user_session['message_id'], "", message)
    print message
    sock.send(message)
    response = sock.recv(1024)
    print response
    user_session['message_id'] = user_session['message_id'] + 1
    MESSAGE_SESSIONS[user] = user_session

def logout():
    sock = connect_to_server()
    message = "QUIT\r\n"
    sock.send(message)
    response = sock.recv(1024)
    print response

def check_server_version():
    sock = connect_to_server()
    message = "VERSION\r\n"
    sock.send(message)
    response = sock.recv(1024)
    print response

def ping_server():
    sock = connect_to_server()
    message = "PING\r\n"
    sock.send(message)
    response = sock.recv(1024)
    print response

def lookup_user():
    username = raw_input("Enter username: ")
    sock = connect_to_server()
    message = "LKUP {0}\r\n".format(username)
    sock.send(message)
    response = sock.recv(1024)
    print response

def list_users():
    sock = connect_to_server()
    message = "LIST\r\n"
    sock.send(message)
    response = sock.recv(1024)
    print response

def connect_to_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER[0], SERVER[1]))
    return sock

def help_menu():
    print("List of commands")
    print("[1] List connect users")
    print("[2] Lookup user")
    print("[3] Ping server")
    print("[4] Check server version")
    print("[5] Send message")
    print("[6] Send Encrypted Message")
    print("[7] Help")
    print("[8] Log Out")
    print("[9] Quit")
    print('[10] Generate encryption key')

def welcome_sequence():
    sock = connect_to_server()
    # username = raw_input("Enter username: ")
    # message = "USER {0}\r\n".format(username)
    sock.send("VERSION\r\n")
    response = sock.recv(1024)
    print response
    message = "USER abass\r\n"
    sock.send(message)
    response = sock.recv(1024)
    print response
    response_code, response_message = response.split(' ', 1)
    if int(response_code) == 000:
        # password = raw_input("Enter password: ")
        # message = "PASS {0}\r\n".format(password)
        message = "PASS abass\r\n"
        sock.send(message)
        response = sock.recv(1024)
        print response
        response_code, response_message = response.split(' ', 1)
        if int(response_code) == 000:
            # port = raw_input("Enter port: ")
            # message = "PORT {0}\r\n".format(port)
            message = "PORT 1045\r\n"
            sock.send(message)
            response = sock.recv(1024)
            print response
            gen_key()
            return True
    return False

def not_implemented(sock, args):
    sock.send('001 Not Implemented\r\n')

def ping(sock, args):
    sock.send('000 Pong\r\n')

def sendmsr(sock, args):
    if args[0]:
        sock.send('000 Message recieved')
        print "From {0}: {1}".format(args[0], args[1].split(" ", 1)[1])
    else:
        sock.send('001 No sender included')


def encryptmsg(sock, args):
    if args[0]:
        sock.send('000 Message recieved')
        print KEYPAIR[0]
        print KEYPAIR[1]
        decrypted_msg = rsa.decrypt(args[1].split(" ", 1)[1], KEYPAIR[1])
        print "From {0}: {1}".format(args[0], args[1].split(" ", 1)[1])
    else:
        sock.send('001 No sender included')




def recieving_message():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', 1045))
    print "Waiting for response"
    while True:
        sock.listen(1)
        s_sock, s_address = sock.accept()
        response = ""
        while not response.endswith('\r\n'):
            response = response + s_sock.recv(1024)
        print response
        sender, command, args = None, None, None
        if response.startswith('#'):
            print response.split(" ", 2)
            sender, command, args = response.split(" ", 2)
            print command
        else:
            command, args = response.split(" ", 1)
        print command.lower()
        func = getattr(__import__(__name__), command.lower(), not_implemented)
        func(s_sock, [sender, args])

        print '> '
    print "stopped recieving_message"

def client_repl():
    #returns a boolean value to determine if a connection was established
    connection_active = welcome_sequence()
    help_menu()
    while connection_active:
        user_input = raw_input('> ')
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
            help_menu()
        elif user_input == 8:
            logout()
            print 'Session Closed'.center(40, '*')
            client_repl()
        elif user_input == 9:
            print 'Good bye!'.center(40, '*')
            if connection_active:
                logout()
            connection_active = False
        elif user_input == 10:
            gen_key()
        else:
            print 'Please select a valid option. Press [7] for help'

    return

# using argparse module process the command line arguments
def get_cli_args():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('hostname', metavar='Hostname', type=str,
                        help='this could be d hostname or ip address of the server')
    parser.add_argument('port', metavar='port', type=int, default=21, nargs='?',
                        help='an integer representing the port number')

    args = parser.parse_args()
    # check the validity of the hostname passed in the process convert the host name to ip addr
    try:
        host = socket.gethostbyname(args.hostname)
    except:
        return False

    return {'hostname': host, 'port': args.port}


def main():
    args = get_cli_args()
    SERVER.append(args['hostname'])
    SERVER.append(args['port'])
    print SERVER
    (pubkey, privkey) = rsa.newkeys(512)
    KEYPAIR.append(pubkey)
    KEYPAIR.append(privkey)
    print "Keys generated"
    threads = []
    threads.append(threading.Thread(target=client_repl, args=()).start())
    threads.append(threading.Thread(target=recieving_message, args=()).start())
    # client_repl()

if __name__ == '__main__':
    main()

import socket
import argparse
import shelve
import hashlib
import threading
from time import sleep

VERSION = '1.0'
CURRENT_USERS = {}
HOSTNAME_TO_USER = {}
ADMINS = []
# NEXT_TO_RECIEVE = []


def add_user_to_db(username, obj):
    db = shelve.open('users', flag='c')
    db[username] = obj
    db.close()


def remove_user_from_db(username):
    db = shelve.open('users', flag='c')
    del db[username]
    db.close()

def get_user(username):
    db = shelve.open('users', flag='c')
    user = db[username]
    db.close()
    return user

def get_db_users():
    db = shelve.open('users', flag='c')
    users = db.keys()
    db.close()
    return users

#class that abstract handling request
class ServerHandler(object):
    def __init__(self, connection):
        self.socket = connection[0]
        self.address = connection[1]
        self.next_to_recieve = []

    '''
    parse out the message the message to get command
    and the argument. The method that handles the
    command will parse out the argument list accordingly
    '''
    def __parse_message(self, message):
        message = message.rstrip() #drops the delimeter \r\n
        parsed_message = message.split(' ', 1)
        if parsed_message[0].startswith('#'):
            parsed_message = parsed_message[1].split(' ', 1)
        if len(parsed_message) == 1:
            parsed_message.append(None)
        return(parsed_message)

    # helper method that checks if a user is logged in
    def __logged_in(self):
        return(self.address[0] in  HOSTNAME_TO_USER.keys())

    #helper method to validate state and check if user is logged in
    def __validate_state_and_login_status(self, command):
        if self.__logged_in(): # check if a user is logged in
            # this is the CONN EST state user can accept all commands
            # if in ADMIN AUTH state the next to recieve is a PASS
            if len(self.next_to_recieve) == 0 or command in self.next_to_recieve:
                return True
            else:
                self.__send_response("100 Command not allowed")
                self.__close_conn()
                return False
        elif command == 'VERSION' or command == 'QUIT' or command in self.next_to_recieve:
        #users can still send version and quit if they are not logged in
        #when user is in the AUTH state they are not logged in but can send
        #USER and PASS. this would have been set in the next to recieve.
            return True
        else:
        #all other commands
            self.__send_response("100 Command not allowed")
            self.__close_conn()
            return False

    '''
    This a default method handles requests for command
    that have not been Implemented.
    '''
    def __not_implemented(self, args):
        self.__send_response("001 Command not Implemented")
        return True

    #helper method for sending reply message
    def __send_response(self, message):
        try:
            self.socket.send("{0}\r\n".format(message))
        except:
            return

    # helper method to send message- used by both SENDMSR and ENCRYPTMSG
    def __send_message(self, command, args):
        user = args.split('#', 1)[0] #get user from the header
        current_users = CURRENT_USERS.keys()
        if user in current_users:
            self.__send_response("000 Message received")
            self.__close_conn()
            user = CURRENT_USERS.get(user)
            sending_user = HOSTNAME_TO_USER[self.address[0]]
            sending_user = "#{0}".format(sending_user)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((user['address'][0], int(user['address'][1])))
            sock.send("{0} {1} {2}\r\n".format(sending_user, command, args))
            response = sock.recv(1024)
            print response
            sock.close()
        else:
            self.__send_response("001 User not found")
            self.__close_conn()

    '''
    helper method to close connnection
    '''
    def __close_conn(self):
        self.socket.close()
        self.socket = None

    '''
    USER
    message use to authenticate/registration a user
    '''
    def _user(self, args):
        if args == None: # if no argument is passed
            self.__send_response("100 No username passed")
            return
        if args in CURRENT_USERS.keys(): # check if user has already been authenticated
            self.__send_response("100 User already authenticated")
            return
        if args in get_db_users(): # if use exist in our database
            self.__send_response("000 User found please send password")
            self.user_registration = False
        else: #user does not exist in our database
            self.__send_response("001 User not found sending password would create user")
            self.user_registration = True
        self.username = args
        #remove USER from next to recieve
        self.next_to_recieve.remove('USER')
        #set PASS to next to recieve
        self.next_to_recieve.append('PASS')
        return

    '''
    PASS
    command used to send password to server
    '''
    def _pass(self, args):
        if args == None:
            self.__send_response("100 No password passed")
            return
        #convert the passed password to hash before storing
        sha_digest = hashlib.sha256(args).digest()
        #store password as hex
        password_hash = sha_digest.encode('hex')
        # if user is not registered add them to the DB
        if self.user_registration:
            add_user_to_db(self.username, { 'password': password_hash, 'admin': False })
            HOSTNAME_TO_USER[self.address[0]] = self.username
            # DB.sync()
            self.__send_response("000 User authenticated")
        else: # if user is already registered authenticate
            if get_user(self.username)['password'] == password_hash:
                HOSTNAME_TO_USER[self.address[0]] = self.username
                self.__send_response("000 User authenticated")
            else:
                self.__send_response("001 Bad password")
        #remove PASS from next to recieve
        self.next_to_recieve.remove('PASS')
        return


    '''
    PORT
    command used to establish a port with server to
    sending messages to a client
    '''
    def _port(self, args):
        if args == None: # if no argument is passed
            self.__send_response("100 No port passed")
            return
        #check for valid port range
        hostname = self.address[0]
        username = HOSTNAME_TO_USER[hostname]
        CURRENT_USERS[self.username] = {'address': (hostname, args), 'key': ''}
        self.__send_response("000 User port added")
        self.__close_conn()

    '''
    KEY
    command used to establish a pub key with server
    '''
    def _key(self, args):
        if args == None: # if no argument is passed
            self.__send_response("100 No key passed")
            return
        username = HOSTNAME_TO_USER[self.address[0]]
        CURRENT_USERS[username]['key'] = args
        self.__send_response("000 User encryption key created")
        #validate the key that is passed
        self.__close_conn()

    '''
    LIST
    command used to list all active users
    '''
    def _list(self, args):
        current_users = CURRENT_USERS.keys()
        self.__send_response("000 " + ','.join(current_users))
        self.__close_conn()
        return

    '''
    LKUP
    command used to look up info about an
    user
    '''
    def _lkup(self, args):
        if not args:
            self.__send_response("100 Username not passed")
            self.__close_conn()
            return
        current_users = CURRENT_USERS.keys()
        if args in current_users:
            self.__send_response("000 {0}#{1}".format(args, CURRENT_USERS[args]['key']))
        else:
            self.__send_response("001 User not found")
        self.__close_conn()

    '''
    PING
    command used to test if another node is active
    '''
    def _ping(self, args):
        self.__send_response("000 Pong")
        self.__close_conn()

    '''
    SENDMSR
    command used to send messages to a user
    '''
    def _sendmsr(self, args):
        if not args:
            self.__send_response("100 Message not passed")
            self.__close_conn()
            return
        self.__send_message('SENDMSR', args)

    '''
    ENCRYPTMSG
    command for sending encrypted messages
    '''
    def _encryptmsg(self, args):
        if not args:
            self.__send_response("100 Message not passed")
            self.__close_conn()
            return
        self.__send_message('ENCRYPTMSG', args)

    '''
    CONFMSG
    Command for confirming message
    '''
    def _confmsg(self, args):
        if not args:
            self.__send_response("100 Argument not passed")
            self.__close_conn()
            return
        user_name, number = args.split(' ', 1)
        current_users = CURRENT_USERS.keys()
        if user_name in current_users:
            if not number:
                self.__send_response("001 Message ID not passed")

            self.__send_response("000 Message received")
            self.__close_conn()
            user = CURRENT_USERS.get(user_name)
            sending_user = HOSTNAME_TO_USER[self.address[0]]
            sending_user = "#" + sending_user
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((user['address'][0], int(user['address'][1])))
            sock.send("{0} CONFMSG {1}\r\n".format(sending_user, args))
            response = sock.recv(1024)
            print response
            sock.close()
        else:
            self.__send_response("001 User not found")
            self.__close_conn()

    '''
    BROADCAST
    Allows an admin user to send a message to all connected users
    '''
    def _broadcast(self, args):
        #check if message is passed
        if not args:
            self.__send_response("100 Message not passed")
            self.__close_conn()
            return

        #get originator of message
        sending_user = HOSTNAME_TO_USER[self.address[0]]

        #check if user is in admin state
        if not sending_user in ADMINS:
            self.__send_response("001 Unauthorized request")
            self.__close_conn()
            return

        self.__send_response("000 Message received")
        self.__close_conn()
        users = HOSTNAME_TO_USER.keys()
        index = users.index(self.address[0])
        users.pop(index)
        for i in users:
            user_name = HOSTNAME_TO_USER[i]
            user = CURRENT_USERS.get(user_name)
            sending_user = HOSTNAME_TO_USER[self.address[0]]
            sending_user = '#' + sending_user
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((user['address'][0], int(user['address'][1])))
            sock.send("{0} BROADCAST {1}\r\n".format(sending_user, args))
            response = sock.recv(1024)
            print response
            sock.close()

    '''
    ADMIN
    activate admin mode
    '''
    def _admin(self, args):
        username = HOSTNAME_TO_USER[self.address[0]]
        # user = DB.get(username)
        user = get_user(username)
        if user.get('admin'):
            ADMINS.append(username)
            self.__send_response("000 Admin mode activated")
        else:
            self.__send_response("001 You do not have admin access")
        self.__close_conn()
        return

    '''
    ADDADMIN
    Add a user to the list of admin users
    '''
    def _addadmin(self, args):
        #check if a username is passed
        if not args:
            self.__send_response("001 User not passed")
            self.__close_conn()
            return
        # name is passed but not in database
        if not args in get_db_users():
            self.__send_response("001 User not found")
            self.__close_conn()
            return

        sender = HOSTNAME_TO_USER[self.address[0]]
        # check if user is an admin
        if sender in ADMINS:
            if args in get_db_users():
                if args in ADMINS:
                    self.__send_response("001 User is already an admin")
                else:
                    ADMINS.append(args)
                    user_obj = get_user(args)
                    user_obj['admin'] = True
                    add_user_to_db(args, user_obj)
                    self.__send_response("000 User granted admin access")
            else:
                self.__send_response("001 User not found")
        else:
            self.__send_response("001 You do not have admin access")
        self.__close_conn()
        return

    '''
    KICK
    remove a user from the logged in users
    '''
    def _kick(self, args):
        #check if an argument is passed
        if not args:
            self.__send_response("001 User not passed")
            self.__close_conn()
            return

        sending_user = HOSTNAME_TO_USER[self.address[0]]

        #check if current user is in ADMIN state
        if not sending_user in ADMINS:
            self.__send_response("001 Unauthorized request")
            self.__close_conn()
            return

        #check if user is logged in
        if not args in CURRENT_USERS.keys():
            self.__send_response("001 User not logged in")
            self.__close_conn()
            return

        #cannot remove your session
        if sending_user == args:
            self.__send_response("001 Terminate your session with a QUIT")
            self.__close_conn()
            return

        #log out user
        user = CURRENT_USERS.pop(args)
        HOSTNAME_TO_USER.pop(user['address'][0])
        self.__send_response("000 User session terminated")
        self.__close_conn()
        return

    '''
    DELETEUSER
    REmove a registered user from the user datebase
    '''
    def _deleteuser(self, args):
        #check if a username is passed
        if not args:
            self.__send_response("100 User not passed")
            self.__close_conn()
            return

        #get originator of message
        sending_user = HOSTNAME_TO_USER[self.address[0]]

        #check if user is in admin state
        if not sending_user in ADMINS:
            self.__send_response("001 Unauthorized request")
            self.__close_conn()
            return

        # name is passed but not in database
        if not args in get_db_users():
            self.__send_response("001 User not found")
            self.__close_conn()
            return

        #user cannot delete themselves
        if sending_user == args:
            self.__send_response("001 Terminate your session with a QUIT")
            self.__close_conn()
            return
        # remove user from the database of users
        # del DB[args]
        # DB.sync()
        remove_user_from_db(args)
        #if user is logged in we want to remove them from list of active users
        if args in CURRENT_USERS.keys():
            user = CURRENT_USERS.pop(args)
            HOSTNAME_TO_USER.pop(user['address'][1])
        # if user is an admin, remove them
        if args in ADMINS:
            index = ADMINS.index(args)
            ADMINS.pop(index)
        self.__send_response("000 User removed")
        self.__close_conn()
        return


    '''
    VERSION
    this command is used to query the server of the version
    it is running
    '''
    def _version(self, args):
        if self.__logged_in():
            self.__send_response("001 "+VERSION)
            self.__close_conn()
        else: # if user is not logged in set next to recieve as USER
            self.next_to_recieve.append('USER')
            self.__send_response("000 "+VERSION)
        return

    '''
    QUIT command
    '''
    def _quit(self, args):
        # remove user from list of connected users
        try:
            username = HOSTNAME_TO_USER.pop(self.address[0])
        except KeyError:
            return
        user = CURRENT_USERS.pop(username)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((user['address'][0], int(user['address'][1])))
        sock.send("QUIT\r\n")
        response = sock.recv(1024)
        print response
        self.__send_response("000 Closing connection")
        self.__close_conn()
        return

    '''
    EXIT command
    this command remove a user from the admin state
    '''
    def _exit(self, args):
        user = HOSTNAME_TO_USER[self.address[0]]
        if user in ADMINS:
            index = ADMINS.index(user)
            ADMINS.pop(index)
            self.__send_response("000 Admin mode exit")
        else:
            self.__send_response("001 User is not in ADMIN state")
        self.__close_conn()
        return



    '''
    handles request after a connection is established
    '''
    def handle(self):
        while self.socket:
            message = ""
            #read from socket till the delimeter
            while not message.endswith('\r\n'):
                message += self.socket.recv(1024)
            command, arguments = self.__parse_message(message)
            '''
            user is not required to be logged in to send
            VERSION, USER or PASS commands
            '''
            print command + " comand recieved"
            if self.__validate_state_and_login_status(command):
                command = command.lower()
                func = getattr(self, '_'+command, self.__not_implemented)
                func(arguments)
            else:
                if self.socket:
                    self.socket.send('001 In wrong state\r\n')
                    self.__close_conn()
                break

#prune active members if they are no longer running
def client_query():
    while True:
        #loop throug all clients
        users_to_remove =  []
        for host in HOSTNAME_TO_USER:
            username = HOSTNAME_TO_USER[host]
            user = CURRENT_USERS[username]
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((user['address'][0], int(user['address'][1])))
                sock.send("PING\r\n") #send a ping message to each
                response = sock.recv(1024)
                code, message = response.rstrip('\r\n').split(' ', 1)
                print message
            except: #exception is throw in the client is no longer active
                #remove user from active list
                users_to_remove.append((host, username))
        for item in users_to_remove:
            HOSTNAME_TO_USER.pop(item[0])
            CURRENT_USERS.pop(item[1])
            if item[1] in ADMINS: #clear user from admin mode if they are in admin mode
                index = ADMINS.index(item[1])
                ADMINS.pop(index)
        sleep(60) #check everyminute


# process command line arguments
def get_cli_args():
    parser = argparse.ArgumentParser(description='SChaP Client')
    parser.add_argument('--port', metavar='port', type=int, default=6789, help='This is the port of the SChaP server is listening on')

    args = parser.parse_args()

    return {'hostname': '', 'port': args.port}


def main():
    p_args = get_cli_args()
    if not p_args:
        print "Cannot resolve hostname"
        exit(0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((p_args['hostname'], p_args['port']))
    threads = []
    #thread handling period query of client to see if they are still active
    threads.append(threading.Thread(
        target=client_query
    ).start())
    print 'Server is running...'
    while True:
        sock.listen(1)
        client = sock.accept()
        handler = ServerHandler(client)
        #CONCURRENT
        threads.append(threading.Thread(
            target=handler.handle
        ).start())
        print 'Thread created for'
        print client[1]


if __name__ == '__main__':
    main()

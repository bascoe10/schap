import socket
import argparse
import shelve
import hashlib

VERSION = '1.0'
DB = shelve.open('users')
CURRENT_USERS = {}
HOSTNAME_TO_USER = {}
ADMINS = {}
# NEXT_TO_RECIEVE = []

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

    '''
    This a default method handles requests for command
    that have not been Implemented.
    '''
    def __not_implemented(self, args):
        self.__send_response("001 Command not Implemented")
        return True

    def __send_response(self, message):
        try:
            self.socket.send("{0}\r\n".format(message))
        except:
            return

    def __send_message(self, args):
        print args
        user = args.split('#', 1)[0]
        current_users = CURRENT_USERS.keys()
        if user in current_users:
            self.__send_response("000 Message received")
            self.__close_conn()
            user = CURRENT_USERS.get(user)
            sending_user = HOSTNAME_TO_USER[self.address[0]]
            sending_user = "#{0}".format(sending_user)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((user['address'][0], int(user['address'][1])))
            sock.send("{0} SENDMSR {1}\r\n".format(sending_user, args))
            response = sock.recv(1024)
            print response
            sock.close()
        else:
            self.__send_response("001 User not found")
            self.__close_conn()

    '''
    close connnection
    '''
    def __close_conn(self):
        self.socket.close()
        self.socket = None

    '''
    USER
    message use to authenticate/registration a user
    '''
    def _user(self, args):
        print 'user received'
        if args == None: # if no argument is passed
            self.__send_response("100 No username passed")
            return
        if args in CURRENT_USERS.keys(): # check if user has already been authenticated
            self.__send_response("100 User already authenticated")
            return
        if args in DB.keys(): # if use exist in our database
            self.__send_response("000 User found please send password")
            self.user_registration = False
        else: #user does not exist in our database
            self.__send_response("001 User not found sending password would create user")
            self.user_registration = True
        self.username = args
        self.next_to_recieve.remove('USER')
        self.next_to_recieve.append('PASS')
        return

    # TODO: Fill in method
    def _pass(self, args):
        print 'pass received'
        if args == None:
            self.__send_response("100 No password passed")
            return
        sha_digest = hashlib.sha256(args).digest()
        password_hash = sha_digest.encode('hex')

        if self.user_registration:
            DB[self.username] = password_hash
            HOSTNAME_TO_USER[self.address[0]] = self.username
            DB.sync()
            self.__send_response("000 User authenticated")
        else:
            if DB[self.username] == password_hash:
                HOSTNAME_TO_USER[self.address[0]] = self.username
                self.__send_response("000 User authenticated")
            else:
                self.__send_response("001 Bad password")
        self.next_to_recieve.remove('PASS')
        return


    # TODO: Fill in method
    def _port(self, args):
        if args == None: # if no argument is passed
            self.__send_response("100 No port passed")
            return
        hostname = self.address[0]
        username = HOSTNAME_TO_USER[hostname]
        CURRENT_USERS[self.username] = {'address': (hostname, args)}
        self.__send_response("000 User port added")
        self.socket.close()
        self.socket = None

    # TODO: Fill in method
    def _key(self, args):
        if args == None: # if no argument is passed
            self.__send_response("100 No key passed")
            return
        username = HOSTNAME_TO_USER[self.address[0]]
        CURRENT_USERS[username]['key'] = args
        self.__send_response("000 User encryption key created")
        self.socket.close()
        self.socket = None

    # TODO: Fill in method
    def _list(self, args):
        current_users = CURRENT_USERS.keys()
        self.__send_response("001 " + ','.join(current_users))
        self.socket.close()
        self.socket = None
        return

    # TODO: Fill in method
    def _lkup(self, args):
        current_users = CURRENT_USERS.keys()
        if args in current_users:
            self.__send_response("000 {0}#{1}".format(args, CURRENT_USERS[args]['key']))
        else:
            self.__send_response("001 User not found")
        self.socket.close()
        self.socket = None

    # TODO: Fill in method
    def _ping(self, args):
        self.__send_response("000 Pong")
        self.socket.close()
        self.socket = None

    # TODO: Fill in method
    def _sendmsr(self, args):
        self.__send_message(args)

    # TODO: Fill in method
    def _encryptmsg(self, args):
        self.__send_message(args)

    # TODO: Fill in method
    def _confmsg(self, args):
        return

    # TODO: Fill in method
    def _broadcast(self, args):
        return

    # TODO: Fill in method
    def _admin(self, args):
        username = HOSTNAME_TO_USER[self.address[0]]
        if username in ADMINS:
            self.__send_response("000 Admin mode activated")
        else:
            self.__send_response("001 You do not have admin access")
        self.socket.close()
        self.socket = None
        return

    # TODO: Fill in method
    def _addadmin(self, args):
        username = HOSTNAME_TO_USER[self.address[0]]
        if username in ADMINS:
            if args in DB.keys():
                self.__send_response("000 User granted admin access")
            else:
                self.__send_response("001 User not found")
        else:
            self.__send_response("001 You do not have admin access")
        self.socket.close()
        self.socket = None
        return

    # TODO: Fill in method
    def _kick(self, args):
        user = CURRENT_USERS.pop(args)
        HOSTNAME_TO_USER.pop(user['address'][0])
        self.__send_response("000 User removed")
        self.socket.close()
        self.socket = None
        return

    # TODO: Fill in method
    def _deleteuser(self, args):
        user = CURRENT_USERS.pop(args)
        del DB[args]
        DB.sync()
        HOSTNAME_TO_USER.pop(user['address'][1])
        self.__send_response("000 User removed")
        self.socket.close()
        self.socket = None
        return


    '''
    VERSION
    this command is used to query the server of the version
    it is running
    '''
    def _version(self, args):
        print 'version command received'
        self.__send_response("000 "+VERSION)
        if self.address[0] in HOSTNAME_TO_USER.keys():
            self.socket.close()
            self.socket = None
        else:
            self.next_to_recieve.append('USER')
        return

    '''
    QUIT command
    '''
    def _quit(self, args):
        print 'quit command received'
        # remove user from list of connected users
        username = HOSTNAME_TO_USER.pop(self.address[0])
        user = CURRENT_USERS.pop(username)
        self.__send_response("000 Closing connection")
        self.socket.close()
        self.socket = None
        return

    '''
    handles request after a connection is established
    '''
    def handle(self):
        while self.socket:
            message = ""
            while not message.endswith('\r\n'):
                message += self.socket.recv(1024)
            command, arguments = self.__parse_message(message)
            #check if command is valid to be recieved
            if len(self.next_to_recieve) != 0 and not(command in self.next_to_recieve):
                print "Next to recieve {0}".format(",".join(self.next_to_recieve))
                print "Recieved {0}".format(command)
                self.socket.send('001 In wrong state\r\n')
                self.socket.close()
                break
            '''
            user is not required to be logged in to send
            VERSION, USER or PASS commands
            '''
            if command == 'VERSION' or command in self.next_to_recieve or self.address[0] in  HOSTNAME_TO_USER.keys():
                command = command.lower()
                func = getattr(self, '_'+command, self.__not_implemented)
                func(arguments)
            else:
                self.socket.send('001 Please proper auth steps authenticate\r\n')
                self.socket.close()
                break




def get_cli_args():
    parser = argparse.ArgumentParser(description='Please pass the required arguments')
    parser.add_argument('port', metavar='port', type=int,
                        help='an integer representing the port number')

    args = parser.parse_args()
    host = ''
    return {'hostname': host, 'port': args.port}

def main():
    p_args = get_cli_args()
    if not p_args:
        print "Cannot resolve hostname"
        exit(0)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((p_args['hostname'], p_args['port']))

    while True:
        print 'Logged in users'
        print CURRENT_USERS
        print HOSTNAME_TO_USER
        print 'end'
        sock.listen(1)
        client = sock.accept()
        print client
        handler = ServerHandler(client)
        handler.handle()

if __name__ == '__main__':
    main()

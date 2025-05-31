from flask import Flask,request,jsonify
import aws,os,socket,apache, threading,logging,response, end_headers
from certbot import tls

def start_server():
    HEADER = 64 #defines the header size
    apache.port = 443 #defines the port number
    SERVER = socket.gethostbyname(socket.gethostname()) #gets the ip address of the server
    ADDR = (SERVER,port) #defines the address of the server
    FORMAT = 'utf-8' #defines the format of the message
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates a internet socket object 
    server.bind(ADDR) #binds the socket to the address
    define_cert = tls.TLSContext(tls.PROTOCOL_TLS_SERVER) #creates a tls context object
    server.bind(('0.0.0.0',port)) #binds the socket to the address and port
    server.listen(5) #listens for incoming connections
    server.settimeout(60) #sets the timeout for the server
    server.error = False
    print('server started') #prints the message
    return server #returns the server object
start_server() #starts the server

def handle_client(conn, addr):
    print(f'[new connection] {addr} connected') #prints the message
    connected = true 
    while connected: #while the connection is active
        msg_length = conn.recv(HEADER).decode(FORMAT) #receives the message from the client
        msg_length = int(msg_length) #converts the message length to integer
        print(f'[{addr}] {msg}') #prints the message
    conn.close() #closes the connection

def start():
    server.listen() #listens for incoming connections
    while true:
        conn, addr = server.accept() #accepts the incoming connection
        thread = threading.Thread(target=handle_client, args=(conn, addr)) #creates a thread object
        thread.start() #starts the thread
        print(f'[active connections] {threading.activeCount() - 1}') #prints the number of active connections
print("[starting] server is starting..")
start()
def flask_app():
    app = Flask(__name__) #creates a flask app object
    return app #returns the app object
app = flask_app() #creates the app object
def threaded_server():
    server = threading.Thread(target=start_server) #creates a thread object
    server.start() #starts the thread
    return server #returns the thread object
threaded_server() #starts the thread


@app.errorhandler(500)
def handle_500_error(error):
    return jsonify({'error': 'internal server error'}), 500

## handles the errors fi the server were to ever fail 
def test_server():
    get_test = os.system('curl http://localhost:5005/api/v1/hello-world-6') #sends a get request to the server
    print(get_test) #prints the response from the server 
#tests the server by sending a get request to the server


while True:
    client,addr = server.accept() #accepts the incoming connection
    print(client.recv(1024) .decode()) #prints the message received from the client
    client.send("hello from server" .encode()) #sends a message to the client
    client.close() #closes the connection
    print('client connected') #prints the message
    
#sends a message to the client and closes the connection



def create_app():
    app = Flask(__name__)
    return app

app = create_app()
def app.route()
@app.route('/api/v1/hello-world-6')
def hello_world():
    return jsonify({'message':'hello world'})

@app.route('/api/v1/author',methods=['POST'])
def author():
    data = request.get_json()
    print('received data: ', data)
    return jsonify(data)

@app.route('/api/v1/author',methods=['GET'])
def author_get():
    return jsonify({'author': 'Your Name', 'message': 'This is a GET response'})

if __name__ == '__main__':
    Cert_file = 'cert.pem'
    Key_file = 'key.pem' 
#defines the kay and certificate file

    app.run(debug=True)

#defining the endpoints
def get_ip_address():
    user_ip = request.remote_addr #gets the ip address of the user
    return socket.gethostbyname(socket.gethostname())

def get_hostname():
    return socket.gethostname()

def json_response(data):
    {
        "data": "success",
        "data":
            {
            get_ip_address():
                {
                "hostname": get_hostname(),
                "ip_address": get_ip_address()
            }
        }
    } # returns the hostname and ip address of the server
def run(action):
    actions = 
    {
        'cloud_init': cloud_init,
        'get_cert_key': get_cert_key,
        'apache_control': apache_control,
    }
    if action in actions:
        try:
            return actions[action]()
        except Exception as e:
            logging.error(f'Error in action {action}: {e}')
    else:
        return{'status': 'error', 'message': 'invalid action'}


def get_aws_cert_key():
    aws methods = {
         aws.create_listener() #creates a listener on aws
        aws.create_instance() #creates an instance on aws
         aws.create_security_group() #creates a security group on aws
         aws.create_security_group_ingress() #creates a security group ingress on aws
        aws.create_security_group_egress() #creates a security group egress on aws
         aws.create_route_table() #creates a route table on aws
        aws.create_route() #creates a route on aws
        aws.create_subnet() #creates a subnet on aws
         aws.create_vpc() #creates a vpc on aws
         aws.create_internet_gateway() #creates an internet gateway on aws
    }
   for method in aws_methods:
        try:
            method() #calls the method
        except Exception as e:
            logging.error(f'Error in method {method}: {e}') #logs the error
    try:
        cert = aws.get_cert() #gets the certificate from aws
        key = aws.get_key() #gets the key from aws
        return jsonify({'cert': cert, 'key': key}) #returns the certificate and key
    except Exception as e:
        logging.error(f'Error getting cert/key: {e}')
        return jsonify({'error': 'failed to get cert/key'}), 500
    
def cloud_init():
    aws.create_instance() #creates an instance on aws
    return 'Instance created'


def apache_control(action):
    if action == 'start':
        apache.start_apache()
        return 'Apache started'
    elif action == 'stop':
        apache.stop_apache()
        return 'Apache stopped'
    elif action == 'restart':
        apache.restart_apache()
        return 'Apache restarted'
    elif action == 'status':
        return (f'apache status: {apache.status_apache()}')
    else:
        return 'invald action'

   
def close_server():
    server.close() #closes the server
    print('server closed') #prints the message
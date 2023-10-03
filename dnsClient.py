import argparse
import socket
import time
import random
import binascii
import sys


def parse_arguments():

    #Initialize parser
    parser = argparse.ArgumentParser(description="DNS Client")

    #Adding optional arguments
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout in seconds")
    parser.add_argument("-r", "--max-retries", type=int, default=3, help="Number of Max Retries")
    parser.add_argument("-p", "--port", type=int, default=53, help="The UDP port number of the DNS server")
    parser.add_argument("-mx", action="store_true", help="Send an MX (mail server) query")
    parser.add_argument("-ns", action="store_true", help="Send an NS (name server) query")
    
    # Required arguments
    parser.add_argument("server", metavar="server", type=str, help="IPv4 address of the DNS server in a.b.c.d format") # @ not included here, watch out for issues
    parser.add_argument("name", metavar="name", type=str, help="Domain name to query for")

    #Read arguments from command line
    args = parser.parse_args()
    args.server = args.server.replace("@", "")

    # print(args)
    return args


def create_dns_query(timeout, max_retries, port, mx, ns, server, name):

    # DNS header fields (2 bytes each)
    ID = random.randint(1, 65535)  # You can choose any ID value
    binary_id = bin(ID)[2:]  # [2:] is used to remove the '0b' prefix
    #print("This is the binary id:", binary_id)

    header = binary_id + '0000000100000000' + '0000000000000001' + '0000000000000000' + '0000000000000000' + '0000000000000000'
    # print(header)
    header_int = int(header, 2)
    header_hex = hex(header_int)[2:]
    # print("This is the header in hex:", header_hex)

    # Encode domain name
    labels = name.split('.')
    qname = b''

    for label in labels:
        label_length = len(label)
        qname += bytes([label_length])
        for char in label:
            qname += bytes([ord(char)])  # Encode characters as ASCII values

    qname += b'\x00'
    qnamebinary = bin(int.from_bytes(qname, byteorder='big'))[2:]

    global qnamebinsize

    qname_size_in_bytes = len(qname)
    qnamebinsize = qname_size_in_bytes * 8

    # print("qnamebinary:", qnamebinsize)
    qname = qname.hex()

    # DNS question fields (4 bytes each)
    global QTYPE
    QTYPE = '0000000000000001'
    if (mx and ns == False):
        QTYPE = '0000000000000001' #Type A

    if (ns):
        QTYPE = '0000000000000010'

    if(mx):
        QTYPE = '0000000000001111'
        
    else:
        QTYPE = '0000000000000001'

    QTYPE_int = int(QTYPE, 2)
    QTYPE_hex = format(QTYPE_int, '04x')

    QCLASS = '0000000000000001'  # IN (Internet)
    QCLASS_int = int(QCLASS, 2)
   
    QCLASS_hex = format(QCLASS_int, '04x')

    # Build DNS question section
    question = QTYPE_hex + QCLASS_hex

    # Combine header and question
    query = header_hex + qname + question

    global qname_qtype_qclass_size
    global qname_qtype_qclass
    qname_qtype_qclass = qnamebinary + QTYPE + QCLASS
    qname_qtype_qclass_size = len(qname_qtype_qclass)

    #print('this is the full query:', query)
    
    return query

# Parse the DNS response
def parse_dns_response(response):
    global id_hex, flags_hex, qdcount_hex, ancount_hex, nscount_hex, arcount_hex, resps, add_resps

    response = response.hex()
    header = response[:24]
    id_hex = header[:4]
    flags_hex = header[4:8]
    qdcount_hex = header[8:12]
    ancount_hex = header[12:16]
    nscount_hex = header[16:20]
    arcount_hex = header[20:24]

    # We use this bit to know if the answer is authoritative or not
    global AA
    response_bytes = bytes.fromhex(response)
    response_binary = bin(int.from_bytes(response_bytes, byteorder='big'))[2:]
    AA = response_binary[21:22]



    questions_hex = hex(int(qname_qtype_qclass, 2))[2:]
    questions_hex_size = len(questions_hex)

    dns_response = response[24 + questions_hex_size:]

    resps = []
    resps_number = int(ancount_hex, 16)
    pointer = 1

    global resp_name, resp_type, resp_class, resp_ttl, resp_rdlength, resp_rdata

    for _ in range(resps_number):
        resp_name = dns_response[pointer:pointer + 4]
        resp_type = dns_response[pointer + 4: pointer + 8]
        resp_class = dns_response[pointer + 8 : pointer + 12]
        resp_ttl = dns_response[pointer + 12 : pointer + 20]
        resp_rdlength = dns_response[pointer + 20 : pointer + 24]
        resp_rdata = dns_response[pointer + 24 : pointer + 24 + int(resp_rdlength, 16) * 2]
        # print('This is one response')
        pointer += int(resp_rdlength, 16) * 2 + 24

    # Turning first 16 bits of rdata for the pref into an integer for MX
    global resp_rdata_pref_int
    resp_rdata_pref = resp_rdata[:4]
    resp_rdata_pref_int = int(resp_rdata_pref, 16)
    
    # Get the Alias for MX in bits
    global resp_rdata_alias_MX

    resp_rdata_alias_MX = bytes.fromhex(resp_rdata).decode('latin-1') 
    #print("rdata MX:",resp_rdata_alias_MX)

    #AUTHORATIVE
    count_auth = 0
    num_auth = int(nscount_hex, 16)
    for _ in range(num_auth):
        resp_rdlength = dns_response[pointer + 20 : pointer + 24]
        pointer += int(resp_rdlength, 16) * 2 + 24

    # Additionals
    add_num_resps = int(arcount_hex, 16)
    add_resps = []
    global add_name, add_response_type, add_response_class, add_ttl, add_rdlength, add_rdata

    for _ in range(add_num_resps):
        add_name = dns_response[pointer:pointer + 4]
        add_response_type = dns_response[pointer + 4: pointer + 8]
        add_response_class = dns_response[pointer + 8 : pointer + 12]
        add_ttl = dns_response[pointer + 12 : pointer + 20]
        add_rdlength = dns_response[pointer + 20 : pointer + 24]
        add_rdata = dns_response[pointer + 24 : pointer + 24 + int(add_rdlength, 16) * 2]
        #print('This is one response')
        pointer += int(add_rdlength, 16) * 2 + 24


    #print("rdata MX:",add_rdata_alias_MX)
    bin_flags = bin(int(flags_hex, 16))
    Rcode = int(bin_flags[-4:], 2)

    if Rcode == 1:
        print("ERROR    The name server was unable to interpret the query")
        sys.exit()
    
    if Rcode == 2:
        print("ERROR    Server failure: the name server was unable to process this query due to a problem with the name server")
        sys.exit()
    if Rcode == 3:
        print("ERROR    Name error: meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist")
        sys.exit()
    if Rcode == 4:
        print("ERROR    Not implemented: the name server does not support the requested kind of query")
        sys.exit()
    if Rcode == 5:
        print("ERROR    Refused: the name server refuses to perform the requested operation for policy reasons")
        sys.exit()

    return True

def send_dns_query(query, timeout, max_retries, port, mx, ns, server, name):
    try:

        global received_bool
        received_bool = False

        #Initialize time variables
        start_time = 0
        end_time = 0
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Set a timeout for the socket (optional)
        udp_socket.settimeout(timeout)  # Set the timeout to 5 seconds
        # Send the DNS query to the server
        server_arg = binascii.unhexlify(query)
        tuple_server = (server, port)
        # Write start time
        start_time = time.time()
        udp_socket.sendto(server_arg, tuple_server)
        # Receive the response from the server
        info = udp_socket.recv(8192)

        response = binascii.hexlify(info).decode("utf-8")
        # Write end time
        end_time = time.time()
        # Calculate total response time
        global total_time
        total_time = end_time - start_time
        # Close the socket
        udp_socket.close()
        received_bool = True
        return info

    except socket.timeout:
        print("ERROR    Socket timed out. The DNS server did not respond within the specified timeout.")
    except socket.error as e:
        print("ERROR    Socket error:", e)
    except Exception as e:
        print("ERROR    An error occurred:", e)
        

if __name__ == "__main__":
        args = parse_arguments()

        req_type = 'none'
        if(args.mx and args.ns):
            print("ERROR    You cannot ask for both a mail server and a name server request at the same time.")
            sys.exit()
        if(args.mx):
            req_type = 'mx'
        if(args.ns):
            req_type = 'ns'
        if((args.mx or args.ns) != True):
            req_type = 'A'

        
        print('DnsClient sending request for', args.name) 
        print('Server:', args.server )
        print('Request type:', req_type)
        
        qquery = create_dns_query(args.timeout, args.max_retries, args.port, args.mx, args.ns, args.server, args.name)

        num_retries = 0
        num_max_retries = args.max_retries
        while num_max_retries >= 0:
            query_rec = send_dns_query(qquery, args.timeout, args.max_retries, args.port, args.mx, args.ns, args.server, args.name) #in a loop depending on number of retries
            if(received_bool):
                break
            num_max_retries -= 1
            num_retries += 1


        if(received_bool):
            parsed_res = parse_dns_response(query_rec)
            # print(parsed_res)
            print('Response received  after', total_time, 'seconds (', num_retries, ' retries) ')
            # print("Received response:", query_rec)

            int_ancount = int(ancount_hex, 16)
            if(int_ancount > 0):
                print('***Answer Section (', int_ancount,'records)***')

            # Then, if the response contains A (IP address) records, each should be printed on a line of the form:
            i = 0
            resp_ttl_hex = int(resp_ttl, 16)
            if (AA == 1):
                auth = "auth"
            else:
                auth = "nonauth" 

            for i in range(int_ancount) :
                if(resp_type == '0001'):
                    print('IP    ', resp_rdata, '    ',resp_ttl_hex,'    ',auth,'')
                if(resp_type == '005'):
                    print('CNAME    ', resp_rdata,'    ',resp_ttl_hex,'    ',auth,'')
                if(resp_type == '000f'):
                    print('MX    ',resp_rdata_alias_MX,'    ',resp_rdata_pref_int,'    ',resp_ttl_hex,'    ',auth,'')
                if(resp_type == '0002'):
                    print('NS    ', resp_rdata,'    ',resp_ttl_hex,'    ',auth,'')


            print("***Additional Section ([num-additional] records)***")

            for i in range(int_ancount) :
                if(resp_type == '0001'):
                    print('IP    ', add_rdata, '    ',resp_ttl_hex,'    ',auth,'')
                if(resp_type == '005'):
                    print('CNAME    ', add_rdata,'    ',resp_ttl_hex,'    ',auth,'')
                if(resp_type == '000f'):
                    print('MX    ',resp_rdata_alias_MX,'    ',resp_rdata_pref_int,'    ',resp_ttl_hex,'    ',auth,'')
                if(resp_type == '0002'):
                    print('NS    ', add_rdata,'    ',resp_ttl_hex,'    ',auth,'')
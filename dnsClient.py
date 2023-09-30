import argparse
import socket
import struct
import sys
import time
import random
import binascii


A_TYPE = 1
MX_TYPE = 15
NS_TYPE = 2
CNAME_TYPE = 5

server_ip = "DNS_SERVER_IP_ADDRESS" #MAYBE NEED TO CHANGE THIS
server_port = 53  # DNS typically uses port 53
server_address = (server_ip, server_port)

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
    # print(args)
    return args


def create_dns_query(timeout, max_retries, port, mx, ns, server, name):

    # DNS header fields (2 bytes each)
    ID = random.randint(1, 65535)  # You can choose any ID value
    # print(ID)
    binary_id = bin(ID)[2:]  # [2:] is used to remove the '0b' prefix
    # print(binary_id)
    # ID = hex(ID)[2:]
    # print(ID)
    # id_bytes = ID.to_bytes(2, byteorder='big')  # 2 bytes for ID

    header = binary_id + '0000000100000000' + '0000000000000001' + '0000000000000000' + '0000000000000000' + '0000000000000000'
    # print(header)
    header_int = int(header, 2)
    header_hex = hex(header_int)[2:]
    print(header_hex)

    # QR = format(0b0, '01b')       # 0 for query (not a response)
    # OPCODE = format(0b0000, '04b')  # 4-bit field set to 0 for standard query
    # AA = format(0b0, '01b')       # Authoritative Answer bit (0 for non-authoritative response)
    # TC = format(0b0, '01b')       # Truncation bit (not truncated)
    # RD = format(0b1, '01b')       # Recursion Desired bit (set to 1 to indicate desire for recursion)
    # RA = format(0b0, '01b')       # Recursion Available bit (set to 0 initially)
    # Z = format(0b000, '03b')      # 3-bit reserved field set to 0
    # RCODE = format(0b0000, '04b')  # Response Code (set to 0 for requests)

    # header_binary = QR + OPCODE + AA + TC + RD + RA + Z + RCODE
    # init_header_hex = hex(int(header_binary, 2))  # Convert binary to hexadecimal

    # print(init_header_hex)

    # QDCOUNT = hex(1)[2:]  # Number of Questions (always 1 for our program)
    # ANCOUNT = hex(0)[2:]  # Number of Answer records (initially 0)
    # NSCOUNT = hex(0)[2:]  # Number of Name Server records (initially 0)
    # ARCOUNT = hex(0)[2:]  # Number of Additional records (initially 0)

    # header = ID + init_header_hex + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT
    # # header = (QR, OPCODE, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
    # print(header)

    # Encode domain name
    labels = name.split('.')
    qname = b''

    for label in labels:
        label_length = len(label)
        qname += bytes([label_length])
        for char in label:
            qname += bytes([ord(char)])  # Encode characters as ASCII values

    qname += b'\x00'
    qname = qname.hex() #MAKE SURE THAT WE WANT IN HEX
    # print(qname)

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

    print('THIS IS QTYPE: {}'.format(QTYPE))

    

    QTYPE_int = int(QTYPE, 2)
    # QTYPE_hex = hex(QTYPE_int)[2:]
    QTYPE_hex = format(QTYPE_int, '04x')

    #MIGHT NEED TO HANDLE ERROR WHERE BOTH ARE TRUE
    # QTYPE = query_type
    QCLASS = '0000000000000001'  # IN (Internet)
    QCLASS_int = int(QCLASS, 2)
    # print('this is qclass int')
    # print(QCLASS_int)
    QCLASS_hex = format(QCLASS_int, '04x')
    print(len(QCLASS))
    # print('this is qclass hex')
    print(QCLASS_hex)

    # Build DNS question section
    # question = struct.pack('!HH', QTYPE, QCLASS)
    question = QTYPE_hex + QCLASS_hex
    print(question)

    # qname_bytes = bytes.fromhex(qname)
    # Combine header and question
    # query = header + qname_bytes + question
    query = header_hex + qname + question

    global qname_qtype_qclass_size
    qname_qtype_qclass_size = len(qname + QTYPE + QCLASS)
    print('This is the QNAME QTYPE QCLASS SIZE: {}', qname_qtype_qclass_size)

    print('this is the full query')
    print(query)
    # query_bytes = bytes.fromhex(query)  # Convert hexadecimal string to bytes
    # print(query_bytes)
    return query

def parse_dns_response(response): #not sure i need self here
# Parse the DNS response
# You need to implement this function based on the DNS protocol

# Extract relevant information from the response
# For each record in the Answer, Additional, and Authority sections, if applicable

    response_hex = response.hex()
    print(response_hex)

    #Header
    header = response_hex[:24] #first 24 - 12 bytes #CAN PROBABLY REMOVE THIS AND TRUNCATE DIRECTLY FROM RESPONSEHEX
    id = header[:4]
    flags = header[4:8]
    qdcount = header[8:12]
    ancount = header[12:16]
    nscount = header[16:20]
    arcount = header[20:24]

    #questions
    questions = response_hex[24: 24 + qname_qtype_qclass_size] #HOPEFULLY THIS WORKS

    respdns = response_hex[24 + qname_qtype_qclass_size:]

    ptr = 0 #to iterate through responses

    #extract answers CHANGEEEEEEEE
    rrs = []
    count_rrs = 0
    num_of_rrs = int(ancount, 16)

    while ptr < len(respdns) and count_rrs < num_of_rrs:
        count_rrs += 1
        name = respdns[ptr:ptr + 4]
        response_type = respdns[ptr + 4: ptr + 8]
        response_class = respdns[ptr + 8: ptr + 12]
        ttl = respdns[ptr + 12: ptr + 20]
        rdlength = respdns[ptr + 20: ptr + 24]
        rdata = respdns[ptr + 24: ptr + 24 + int(rdlength, 16) * 2]
        print('this is one response')

    rr = { #IS THIS NECESSARY????
        'name': name,
        'response_type': response_type,
        'response_class': response_class,
        'ttl': ttl,
        'rdlength': rdlength,
        'rdata': rdata 
    }

    rrs.append(rr)

    ptr += int(rdlength, 16)*2 + 24

    #NOT SURE IF WE NEED TO ITERATE THROUGH AUTHORATIVE SEE PIC IF NECESSARY

    #extarct additionals
    count_add_rrs = 0
    num_of_add_rrs = int(arcount, 16)
    add_rrs = []

    while ptr < len(respdns) and count_add_rrs < num_of_add_rrs:
        count_add_rrs += 1
        name = respdns[ptr:ptr + 4]
        response_type = respdns[ptr + 4: ptr + 8]
        response_class = respdns[ptr + 8: ptr + 12]
        ttl = respdns[ptr + 12: ptr + 20]
        rdlength = respdns[ptr + 20: ptr + 24]
        rdata = respdns[ptr + 24: ptr + 24 + int(rdlength, 16) * 2]

    add_rr = { #IS THIS NECESSARY????
        'name': name,
        'response_type': response_type,
        'response_class': response_class,
        'ttl': ttl,
        'rdlength': rdlength,
        'rdata': rdata 
    }

    add_rrs.append(add_rr)

    ptr += int(rdlength, 16)*2 + 24

    #RESP OBJ W APPROPRIATE INFO
    response_obj = {
        'id': id,
        'flags': flags,
        'qdcount': qdcount,
        'ancount': ancount,
        'nscount': nscount,
        'arcount': arcount,
        'rrs': rrs,
        'add_rrs': add_rrs
    }

    #ANALYZE RCODE AND RETURN CORRESPONDING ERROR

    flagsbin = bin(int(response_obj['flags'], 16)) #THESE TWO LINES ARE WEIRD
    rcode = int(flagsbin[-4:], 2)

    if rcode == 1:
        raise Exception("The name server was unable to interpret the query")
    elif rcode == 2:
        raise Exception("Server failure: the name server was unable to process this query due to a problem with the name server")
    elif rcode == 3:
        raise Exception("Name error: meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist")
    elif rcode == 4:
        raise Exception("Not implemented: the name server does not support the requested kind of query")
    elif rcode == 5:
        raise Exception("Refused: the name server refuses to perform the requested operation for policy reasons")


    return response_obj


# # Print the response summary
#     print("Response received after [time] seconds ([num-retries] retries)")

#     # Check if there are answers in the response
#     if num_answers > 0:
#         print("***Answer Section ([num-answers] records)***")

#         # Loop through the answer records
#         for record in answer_records:
#             # Print A, CNAME, MX, or NS records accordingly
#             if record.type == A_TYPE:
#                 print("IP\t{}\t{}\tauth".format(record.ip_address, record.ttl))
#             elif record.type == CNAME_TYPE:
#                 print("CNAME\t{}\t{}\tauth".format(record.alias, record.ttl))
#             elif record.type == MX_TYPE:
#                 print("MX\t{}\t{}\t{}\tauth".format(record.alias, record.preference, record.ttl))
#             elif record.type == NS_TYPE:
#                 print("NS\t{}\t{}\tauth".format(record.alias, record.ttl))

#     # Check if there are additional records in the response
#     if num_additional > 0:
#         print("***Additional Section ([num-additional] records)***")

#         # Loop through the additional records
#         for record in additional_records:
#             # Print A, CNAME, MX, or NS records accordingly
#             if record.type == A_TYPE:
#                 print("A\t{}\t{}\tauth".format(record.ip_address, record.ttl))
#             elif record.type == CNAME_TYPE:
#                 print("CNAME\t{}\t{}\tauth".format(record.alias, record.ttl))
#             elif record.type == MX_TYPE:
#                 print("MX\t{}\t{}\t{}\tauth".format(record.alias, record.preference, record.ttl))
#             elif record.type == NS_TYPE:
#                 print("NS\t{}\t{}\tauth".format(record.alias, record.ttl))

#     # If no records found, print NOTFOUND
#     if num_answers == 0 and num_additional == 0:
#         print("NOTFOUND")       

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

        # upd_socket.connect() #MAYBE IMPLEMENT THIS

        # Send the DNS query to the server
        server_arg = binascii.unhexlify(query)
        tuple_server = (server, port)

        print('IT GOT HERE1')

        # Write start time
        start_time = time.time()
        udp_socket.sendto(server_arg, tuple_server)

        print('it got here 11111')

        # Receive the response from the server
        # response, tuple_server = udp_socket.recvfrom(1024)  # Adjust buffer size as needed
        info = udp_socket.recv(8192) # Check if it works with 1024 buffer
        # Write end time
        end_time = time.time()
        # Calculate total response time
        global total_time
        total_time = end_time - start_time

        # parsed_res = parse_dns_response(info)

        # print("Received response:", parsed_res)
        # print("Received response IN:", info)

        # parsed_res = parse_dns_response(info)

        # Close the socket
        udp_socket.close()

        
        received_bool = True

        return info

    except socket.timeout:
        print("Socket timed out. The DNS server did not respond within the specified timeout.")
    except socket.error as e:
        print("Socket error:", e)
    except Exception as e:
        print("An error occurred:", e)
        

if __name__ == "__main__":
        args = parse_arguments()

        # Access the parsed arguments
        # print("Timeout:", args.timeout)
        # print("Max Retries:", args.max_retries)
        # print("Port:", args.port)
        # print("MX Query:", args.mx)
        # print("NS Query:", args.ns)
        # print("Server:", args.server)
        # print("Name:", args.name)

        # print(QTYPE)

        print(args.ns)
        req_type = 'none'
        if(args.mx and args.ns):
            req_type = 'Not possible' #CHANGE THIS FOR CORRECT ERROR MESSAGE AT SOME POINT AND STOP THE REQUEST
        if(args.mx):
            req_type = 'mx'
        if(args.ns):
            req_type = 'ns'
        if((args.mx or args.ns) != True):
            req_type = 'A'

        
        print('DnsClient sending request for', args.name) # should give mcgill
        print('Server:', args.server ) #should give IP ADDRESS
        print('Request type:', req_type)
        
        qquery = create_dns_query(args.timeout, args.max_retries, args.port, args.mx, args.ns, args.server, args.name)
        query_rec = send_dns_query(qquery, args.timeout, args.max_retries, args.port, args.mx, args.ns, args.server, args.name) #in a loop depending on number of retries
        # parsed_res = parse_dns_response(query_rec)

        if(received_bool):
            print('Response  received  after', total_time, 'seconds   ([num-retries]   retries) ')
            print("Received response:", query_rec) #probs wanna replace the received query here by the parsed one

        # if(answers_bool): #NEED ANSWERS BOOL
        #     print('***Answer Section ([num-answers] records)***')

        #     #Then, if the response contains A (IP address) records, each should be printed on a line of the form:
        #     # for(num_answers):
        #     for(len(answers)): #NEED ANSWERS LIST
        #         if(resp_type == 'A'):
        #             print('IP   [ip address]    [seconds can cache]    [auth | nonauth]') #SHOULD I REPLACE THE 'TABS' BY THE ACTUAL TAB CHARACTER t{}
        #         if(resp_type == 'CNAME'):
        #             print('CNAME    [alias]    [seconds can cache]    [auth | nonauth]')
            
            

        # print(qquery)
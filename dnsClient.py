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
    args.server = args.server.replace("@", "")

    # print(args)
    return args


def create_dns_query(timeout, max_retries, port, mx, ns, server, name):

    # DNS header fields (2 bytes each)
    ID = random.randint(1, 65535)  # You can choose any ID value
    # print(ID)
    binary_id = bin(ID)[2:]  # [2:] is used to remove the '0b' prefix
    print("This is the binary id:", binary_id)
    # print(binary_id)
    # ID = hex(ID)[2:]
    # print(ID)
    # id_bytes = ID.to_bytes(2, byteorder='big')  # 2 bytes for ID

    header = binary_id + '0000000100000000' + '0000000000000001' + '0000000000000000' + '0000000000000000' + '0000000000000000'
    # print(header)
    header_int = int(header, 2)
    header_hex = hex(header_int)[2:]
    print("This is the header in hex:", header_hex)

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
    qnamebinary = bin(int.from_bytes(qname, byteorder='big'))[2:]

    global qnamebinsize

    qname_size_in_bytes = len(qname)
    qnamebinsize = qname_size_in_bytes * 8

    print("qnamebinary:", qnamebinsize)
    # global qnamebinsize
    # qnamebinsize = len(qname_size_in_bits)

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

    QTYPE_int = int(QTYPE, 2)
    # QTYPE_hex = hex(QTYPE_int)[2:]
    QTYPE_hex = format(QTYPE_int, '04x')

    #MIGHT NEED TO HANDLE ERROR WHERE BOTH ARE TRUE
    # QTYPE = query_type
    QCLASS = '0000000000000001'  # IN (Internet)
    QCLASS_int = int(QCLASS, 2)
   
    QCLASS_hex = format(QCLASS_int, '04x')
    # Build DNS question section
    # question = struct.pack('!HH', QTYPE, QCLASS)
    question = QTYPE_hex + QCLASS_hex

    # qname_bytes = bytes.fromhex(qname)
    # Combine header and question
    # query = header + qname_bytes + question
    query = header_hex + qname + question

    global qname_qtype_qclass_size
    global qname_qtype_qclass
    qname_qtype_qclass = qnamebinary + QTYPE + QCLASS
    qname_qtype_qclass_size = len(qname_qtype_qclass)

    print('this is the full query:', query)
    
    # query_bytes = bytes.fromhex(query)  # Convert hexadecimal string to bytes
    # print(query_bytes)
    return query

def parse_dns_response(response): #not sure i need self here
# Parse the DNS response
# You need to implement this function based on the DNS protocol

# Extract relevant information from the response
# For each record in the Answer, Additional, and Authority sections, if applicable

    global id_hex, flags_hex, qdcount_hex, ancount_hex, nscount_hex, arcount_hex, resps, add_resps

    response = response.hex()
    header = response[:24]
    id_hex = header[:4]
    flags_hex = header[4:8]
    qdcount_hex = header[8:12]
    ancount_hex = header[12:16]
    nscount_hex = header[16:20]
    arcount_hex = header[20:24]

    questions_hex = hex(int(qname_qtype_qclass, 2))[2:]
    questions_hex_size = len(questions_hex)
    #dns_questions = response[24: 24 + questions_hex_size] #change the names n stuff

    dns_response = response[24 + questions_hex_size:]

    resps = []
    #resps_counter = 0
    resps_number = int(ancount_hex, 16)
    pointer = 1 #to iterate through responses

    global resp_name, resp_type, resp_class, resp_ttl, resp_rdlength, resp_rdata

    for _ in range(resps_number):
        resp_name = dns_response[pointer:pointer + 4]
        resp_type = dns_response[pointer + 4: pointer + 8] #ptr + 4: ptr + 8 (in hex)
        resp_class = dns_response[pointer + 8 : pointer + 12]
        resp_ttl = dns_response[pointer + 12 : pointer + 20]
        resp_rdlength = dns_response[pointer + 20 : pointer + 24]
        resp_rdata = dns_response[pointer + 24 : pointer + 24 + int(resp_rdlength, 16) * 2]
        print('This is one response')
        pointer += int(resp_rdlength, 16) * 2 + 24

        # single_response = { 
        #     'resp_name': resp_name,
        #     'resp_type': resp_type,
        #     'resp_class': resp_class,
        #     'resp_ttl': resp_ttl,
        #     'resp_rdlength': resp_rdlength,
        #     'resp_rdata': resp_rdata 
        # }

        #resps.append(single_response)

    #AUTHORATIVE
    count_auth = 0
    num_auth = int(nscount_hex, 16)
    for _ in range(num_auth):
        resp_rdlength = dns_response[pointer + 20 : pointer + 24]
        pointer += int(resp_rdlength, 16) * 2 + 24



    #extarct additionals
    add_num_resps = int(arcount_hex, 16)
    add_resps = []
    global add_name, add_response_type, add_response_class, add_ttl, add_rdlength, add_rdata
    for _ in range(add_num_resps):
        #resps_counter += 1
        add_name = dns_response[pointer:pointer + 4]
        add_response_type = dns_response[pointer + 4: pointer + 8] #ptr + 4: ptr + 8 (in hex)
        add_response_class = dns_response[pointer + 8 : pointer + 12]
        add_ttl = dns_response[pointer + 12 : pointer + 20]
        add_rdlength = dns_response[pointer + 20 : pointer + 24]
        add_rdata = dns_response[pointer + 24 : pointer + 24 + int(resp_rdlength, 16) * 2]
        print('This is one response')
        pointer += int(resp_rdlength, 16) * 2 + 24

        # add_resp = { #IS THIS NECESSARY????
        #     'add_name': add_name,
        #     'add_response_type': add_response_type,
        #     'add_response_class': add_response_class,
        #     'add_ttl': add_ttl,
        #     'add_rdlength': add_rdlength,
        #     'add_rdata': add_rdata 
        # }
        #add_resps.append(add_resp)

    #RESP OBJ W APPROPRIATE INFO
    # complete_resp = {
    #     'id_hex': id_hex,
    #     'flags_hex': flags_hex,
    #     'qdcount_hex': qdcount_hex,
    #     'ancount_hex': ancount_hex,
    #     'nscount_hex': nscount_hex,
    #     'arcount_hex': arcount_hex,
    #     'resps': resps,
    #     'add_resps': add_resps
    # }

    # response_binary = bin(int.from_bytes(response, byteorder='big'))[2:]
    
    # # Header
    # id = response_binary[:16]
    # flags = response_binary[16:32] #hex :4
    # # Individual flags hex 4:8
    # QR = response_binary[16:17]
    # OPcode = response_binary[17:21]
    # AA = response_binary[21:22]
    # TC = response_binary[22:23]
    # RD = response_binary[23:24]
    # RA = response_binary[24:25]
    # Z = response_binary[25:28]
    # Rcode = response_binary[28:32]

    # qdcount = response_binary[32:48] #hex 8:12
    # ancount = response_binary[48:64] #hex 12:16
    # nscount = response_binary[64:80] #hex 16:20
    # arcount = response_binary[80:96] #hex 20:24

    #questions
    #questions_in_binary = response_binary[96: 96 + qname_qtype_qclass_size] #HOPEFULLY THIS WORKS
    # responses_in_binary = response_binary[96 + qname_qtype_qclass_size:] #hex: 24: 24 + len(hex_qname_qtype_qclass)
    # resps = []
    # #resps_counter = 0
    # resps_number = int(ancount, 2)
    # pointer = 0 #to iterate through responses

    # for _ in range(resps_number):
    #     resp_name = responses_in_binary[pointer:pointer + 16]
    #     resp_type = responses_in_binary[pointer + 16: pointer + 32] #ptr + 4: ptr + 8 (in hex)
    #     resp_class = responses_in_binary[pointer + 32 : pointer + 48]
    #     resp_ttl = responses_in_binary[pointer + 48 : pointer + 80]
    #     resp_rdlength = responses_in_binary[pointer + 80 : pointer + 96 ]
    #     resp_rdata = responses_in_binary[pointer + 96 : pointer + 96 + int(resp_rdlength, 2) * 8]
    #     print('This is one response')
    #     pointer += int(resp_rdlength, 2) * 8 + 96

    #     single_response = { 
    #         'resp_name': resp_name,
    #         'resp_type': resp_type,
    #         'resp_class': resp_class,
    #         'resp_ttl': resp_ttl,
    #         'resp_rdlength': resp_rdlength,
    #         'resp_rdata': resp_rdata 
    #     }

    #     resps.append(single_response)

    # # ptr += int(rdlength, 16)*2 + 24

    # #NOT SURE IF WE NEED TO ITERATE THROUGH AUTHORATIVE SEE PIC IF NECESSARY

    # #extarct additionals
    # #count_add_rrs = 0
    # add_num_resps = int(arcount, 2)
    # add_resps = []


    # for _ in range(add_num_resps):
    #     #resps_counter += 1
    #     add_name = responses_in_binary[pointer:pointer + 16]
    #     add_response_type = responses_in_binary[pointer + 16: pointer + 32]
    #     add_response_class = responses_in_binary[pointer + 32 : pointer + 48]
    #     add_ttl = responses_in_binary[pointer + 48 : pointer + 80]
    #     add_rdlength = responses_in_binary[pointer + 80 : pointer + 96]
    #     add_rdata = responses_in_binary[pointer + 96 : pointer + 96 + int(resp_rdlength, 2) * 8]
    #     print('This is one response')
    #     pointer += int(add_rdlength, 2) * 8 + 96

    #     add_resp = { #IS THIS NECESSARY????
    #         'add_name': add_name,
    #         'add_response_type': add_response_type,
    #         'add_response_class': add_response_class,
    #         'add_ttl': add_ttl,
    #         'add_rdlength': add_rdlength,
    #         'add_rdata': add_rdata 
    #     }
    #     add_resps.append(add_resp)

    # #RESP OBJ W APPROPRIATE INFO
    # complete_resp = {
    #     'id': id,
    #     'flags': flags,
    #     'QR': QR,
    #     'OPcode': OPcode,
    #     'AA': AA,
    #     'TC': TC,
    #     'RD': RD,
    #     'RA': RA,
    #     'Z': Z,
    #     'Rcode': Rcode,
    #     'qdcount': qdcount,
    #     'ancount': ancount,
    #     'nscount': nscount,
    #     'arcount': arcount,
    #     'resps': resps,
    #     'add_resps': add_resps
    # }
    
    #ANALYZE RCODE AND RETURN CORRESPONDING ERROR

    #flagsbin = bin(int(complete_resp['flags'], 16)) #THESE TWO LINES ARE WEIRD
    #rcode = int(flagsbin[-4:], 2)

    bin_flags = bin(int(flags_hex, 16))
    Rcode = int(bin_flags[-4:], 2) #CHANGE ALL OF THIS

    if Rcode == 1:
        raise Exception("The name server was unable to interpret the query")
    if Rcode == 2:
        raise Exception("Server failure: the name server was unable to process this query due to a problem with the name server")
    if Rcode == 3:
        raise Exception("Name error: meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist")
    if Rcode == 4:
        raise Exception("Not implemented: the name server does not support the requested kind of query")
    if Rcode == 5:
        raise Exception("Refused: the name server refuses to perform the requested operation for policy reasons")


    return True


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
        # Write start time
        start_time = time.time()
        udp_socket.sendto(server_arg, tuple_server)
        # Receive the response from the server
        # response, tuple_server = udp_socket.recvfrom(1024)  # Adjust buffer size as needed
        info = udp_socket.recv(8192) # Check if it works with 1024 buffer

        response = binascii.hexlify(info).decode("utf-8")
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
            print(parsed_res)
            print('Response  received  after', total_time, 'seconds (', num_retries, ' retries) ')
            print("Received response:", query_rec) #probs wanna replace the received query here by the parsed one

            int_ancount = int(ancount_hex, 16)
            if(int_ancount > 0): #NEED ANSWERS BOOL
                print('***Answer Section (', int_ancount,'records)***')

            # Then, if the response contains A (IP address) records, each should be printed on a line of the form:
            i = 0
            for i in range(int_ancount) :
                #for(parsed_res['resps']): #NEED ANSWERS LIST
                if(resp_type == '0001'):
                    print('IP   [ip address]    [seconds can cache]    [auth | nonauth]') #SHOULD I REPLACE THE 'TABS' BY THE ACTUAL TAB CHARACTER t{}
                if(resp_type == 'CNAME'):
                    print('CNAME    [alias]    [seconds can cache]    [auth | nonauth]')
                if(resp_type == '000f'):
                    print('MX <tab> [alias] <tab> [pref] <tab> [seconds can cache] <tab> [auth | nonauth]')
                if(resp_type == '0002'):
                    print('NS <tab> [alias] <tab> [seconds can cache] <tab> [auth | nonauth]')


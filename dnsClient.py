import argparse
import socket
import struct
import sys
import time
import random

# DNS query types
A_TYPE = 1
MX_TYPE = 15
NS_TYPE = 2
CNAME_TYPE = 5

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

server_ip = "DNS_SERVER_IP_ADDRESS" #MAYBE NEED TO CHANGE THIS
server_port = 53  # DNS typically uses port 53
server_address = (server_ip, server_port)

#Header Info
    #We recommend that your application use a new random 16-bit number for each request.
    #QR is a 1-bit field that specifies whether this message is a query (0) or a response (1).
    #OPCODE is a 4-bit field that specifies the kind of query in this message. Note: You should set this field to 0, representing a standard query.
    #AA is a bit that is only meaningful in response packets and indicates whether (1) or not (0) the name server is an authority for a domain name in the question section. Note: You should use this field to report whether or not the response you receive is authoritative
    #... (check primer)
class DNS:
    # def __init__(self, args):
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
        print(args)
        return args
    

    def create_dns_query(query_type, name):

        # DNS header fields (2 bytes each)
        ID = random.randint(1, 65535)  # You can choose any ID value

        # DNS header fields (16 bits each)
        QR = 0b0     # 0 for query (not a response)
        OPCODE = 0b0000  # 4-bit field set to 0 for standard query
        AA = 0b0     # Authoritative Answer bit (0 for non-authoritative response)
        TC = 0b0     # Truncation bit (not truncated)
        RD = 0b1     # Recursion Desired bit (set to 1 to indicate desire for recursion)
        RA = 0b0     # Recursion Available bit (set to 0 initially)
        Z = 0b000      # 3-bit reserved field set to 0
        RCODE = 0b0000  # Response Code (set to 0 for requests)
        QDCOUNT = 1  # Number of Questions (always 1 for our program)
        ANCOUNT = 0  # Number of Answer records (initially 0)
        NSCOUNT = 0  # Number of Name Server records (initially 0)
        ARCOUNT = 0  # Number of Additional records (initially 0)

        # Pack the header fields into bytes
        header = struct.pack('!HHHHHH', ID, QR, OPCODE, AA, TC, RD, RA, Z, RCODE, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

        # Encode domain name
        labels = name.split('.')
        qname = b''
        # for label in labels:
        #     qname += bytes([len(label)]) + label.encode()

        for label in labels:
            label_length = len(label)
            qname += bytes([label_length])
            for char in label:
                qname += bytes([ord(char)])  # Encode characters as ASCII values

        qname += b'\x00'
        qname = qname.hex() #MAKE SURE THAT WE WANT IN HEX
        # print(qname)

        # LEFT OFF HERE!!!!!!!!!

        # DNS question fields (4 bytes each)
        QTYPE = query_type
        QCLASS = 1  # IN (Internet)

        # Build DNS question section
        question = struct.pack('!HH', QTYPE, QCLASS)

        # Combine header and question
        query = header + qname + question

        return query

    if __name__ == "__main__":
            args = parse_arguments()

            # Access the parsed arguments
            print("Timeout:", args.timeout)
            print("Max Retries:", args.max_retries)
            print("Port:", args.port)
            print("MX Query:", args.mx)
            print("NS Query:", args.ns)
            print("Server:", args.server)
            print("Name:", args.name)

            # create_dns_query(0x0001, 'www.mcgill.ca')






    
    # def send_dns_query(server_ip, port, query_type, domain, timeout, max_retries):
    # query_id = random.randint(1, 65535)
    # query_packet = create_dns_query(query_id, query_type, domain)

    # with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
    #     client_socket.settimeout(timeout)
    #     retries = 0
    #     while retries < max_retries:
    #         try:
    #             client_socket.sendto(query_packet, (server_ip, port))
    #             start_time = time.time()
    #             response, _ = client_socket.recvfrom(1024)
    #             end_time = time.time()
    #             response_time = end_time - start_time

    #             if struct.unpack('!H', response[0:2])[0] == query_id:
    #                 answers, additional_records = parse_dns_response(response, query_type)
    #                 return response_time, answers, additional_records
    #             else:
    #                 print("ERROR\tReceived response with incorrect query ID.")
    #                 retries += 1
    #         except socket.timeout:
    #             print(f"Retrying query (Retry {retries + 1}/{max_retries})")
    #             retries += 1

    #     print(f"ERROR\tMaximum number of retries ({max_retries}) exceeded.")
    #     return None, None, None

    # def create_dns_query(query_id, query_type, domain):
    # header = struct.pack('!HHHHHH', query_id, (QR << 15) | (OPCODE << 11) | (AA << 10) | (TC << 9) | (RD << 😎 | (RA << 7) | (Z << 4) | RCODE, 1, 0, 0, 0)
    # question = b''

    # for part in domain.split('.'):
    #     question += struct.pack('B', len(part))
    #     for char in part:
    #         question += struct.pack('c', bytes(char, 'utf-8'))

    # question += b'\x00'  # End of domain name
    # question += struct.pack('!HH', query_type, 1)

    # return header + question
    
        

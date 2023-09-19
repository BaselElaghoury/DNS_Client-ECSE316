import argparse
#Header Info
    #We recommend that your application use a new random 16-bit number for each request.
    #QR is a 1-bit field that specifies whether this message is a query (0) or a response (1).
    #OPCODE is a 4-bit field that specifies the kind of query in this message. Note: You should set this field to 0, representing a standard query.
    #AA is a bit that is only meaningful in response packets and indicates whether (1) or not (0) the name server is an authority for a domain name in the question section. Note: You should use this field to report whether or not the response you receive is authoritative
    #... (check primer)
class DNS:
    def __init__(self, args):
        #Initialize parser
        parser = argparse.ArgumentParser()
        #Adding optional arguments
        parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout in seconds")
        parser.add_argument("-r", "--max-retries", type=int, default=3, help="Number of Max Retries")
        parser.add_argument("-p", "--port", type=int, default=53, help="The UDP port number of the DNS server")
        parser.add_argument("-mx", "--port", type=int, default=53, help="The UDP port number of the DNS server")

        #Read arguments from command line
        args = parser.parse_args()

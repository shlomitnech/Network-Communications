from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP
from scapy.all import *


def nslookup(domain, reverse=False):
    try:
        DNS_SERVER = "8.8.8.8"
        UDP_PORT = 53
        if reverse:
            # Reverse DNS lookup
            reversed_address = '.'.join(reversed(domain.split('.'))) + '.in-addr.arpa'
            response = sr1(
                IP(dst=DNS_SERVER) / UDP(dport=UDP_PORT) / DNS(rd=1, qd=DNSQR(qname=reversed_address, qtype='PTR')),
                timeout=5)
            count = response.ancount
            if (count > 0):
                print(f"Address entered: {domain}")

                if response and DNSRR in response:
                    for record in response[DNSRR]:
                        if record.type == 12:  # PTR record for reverse mapping
                            print("Canonical Name: " + str(record.rdata.decode()))  # Assuming it's an A record

            else:
                print("ERROR: Invalid address")


        else:
            # Normal DNS lookup
            response = sr1(
                IP(dst=DNS_SERVER) / UDP(dport=UDP_PORT) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A")),
                timeout=20)
            count = response.ancount # how many responses exist
            if (count > 0):
                print(f"Domain entered: {domain}")
                # loop through all the responses
                for i in range(count):
                    if response[DNSRR][i].type == 5: # print the canonical name
                        print("Name: " + response[DNSRR][i].rdata.decode())
                    else: # print the IP addresses
                        print(f"Address #{i}: {response[DNSRR][i].rdata}")
            else:
                print("ERROR: Invalid domain \n")

    except Exception as msg:
        print(msg)


def main():
    print("To exit the program, type 'EXIT' when prompted for a domain.")

    while True:
        domain = input("\nEnter the domain or IP address you want to look up: ")
        if domain.upper() == "EXIT":
            print("Exiting the program.")
            break

        #ask user if they want to do reverse
        reverse_response = input("Do you want to perform reverse mapping? (yes/no): ").lower()

        if reverse_response == 'yes':
            reverse_mapping = True
        else:
            reverse_mapping = False

        nslookup(domain, reverse_mapping)


if __name__ == "__main__":
    main()

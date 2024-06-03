from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP, TCP
import src.subdomain as sub
import socket
import time

# Define constants
server = "8.8.8.8"
myPort = 5555
UDP_PORT = 53
WHOIS_PORT = 43

# Dictionary for WHOIS servers based on TLD
WHOIS_SERVER = {
   "com": "whois.verisign-grs.com",
   "org": "whois.pir.org",
   "net": "whois.verisign-grs.com",
   "il": "whois.isoc.org.il",
    "uk": "whois.nic.uk",
     "de": "whois.denic.de",
    "fr": "whois.nic.fr",
    "au": "whois.auda.org.au",
    "ca": "whois.ca",
    "ru": "whois.tcinet.ru",
    "br": "whois.registro.br"
}

def is_valid_domain(domain):
    # Regular expression pattern to match domain names
    if not domain: # whitespace
        return False
    pattern = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$'
    return bool(re.match(pattern, domain))

# Function to handle sniffed WHOIS responses
def sniff_response(packet):
   if packet.haslayer(TCP) and packet.haslayer(Raw):
       if packet[TCP].sport == WHOIS_PORT:
           response = packet[Raw].load
           print(response.decode('utf-8'))


# Function to get WHOIS server based on TLD
def get_whois_server(domain):
   tld = domain.split(".")[-1]
   return WHOIS_SERVER.get(tld, "whois.iana.org")


# Function to parse DNS CAA response
def parse_dns_response(response):
   value = response[2:]
   return value[5:] if value.startswith("issue") else None


# Function to read subdomain wordlist file
def read_file(filename):
   try:
       with open(filename, 'r') as f:
           return [line.strip() for line in f if line.strip()]
   except FileNotFoundError:
       print("Wordlist file not found.")
       return []


def CAA(domain):
    # create the DNS query
    query = IP(dst=server) / UDP(dport=UDP_PORT) / DNS(rd=1, qd=DNSQR(qname=domain, qtype='CAA'))
    # Send DNS query packet and receive response
    response = sr1(query, verbose=False, timeout = 3)
    if not response:
        print("ERROR in connecting to server")
        return -1
    count = response.ancount
    if count>0:
        print(f"CAA record for {domain}:")
        for i in range(count):
            if response[DNSRR][i].type == 257:  # print the canonical name
                string = (response[DNSRR][i].rdata.decode())
                print(parse_dns_response(string))
    else:
        print("Error: No response received for CAA")


# # Function to perform DNS mapping
def DNS_MAP(domain):
   try:
       start_time = time.time()  # Record start time
       print(f"\n[+] searching (sub)domains for {domain} using built-in wordlist")
       print(f"[+] using maximum random delay of 10 millisecond(s) between requests\n")

       subdomains = sub.subdomains # get the list
       total_domains = 0
       total_ips = 0
       internal_ips = 0

       for subdomain in subdomains:
           hostname = f"{subdomain}.{domain}" #merge the subdomain with the domain
           dns_request = IP(dst=server) / UDP() / DNS(rd=1, qd=DNSQR(qname=hostname))
           p = 0
           response = sr1(dns_request, verbose=0)
           count = response.ancount
           if (count > 0): # only print the ones that got responses
               for i in range(count):
                   if response[DNSRR][i].type == 1: # A records (Ipv4)
                       if p == 0: # new domain that has the record
                           print("\n" + hostname)
                           total_domains += 1
                       p += 1  # increment
                       total_ips += 1
                       print(f"IP address #{p}: {response[DNSRR][i].rdata}")
                       if response[DNSRR][i].rdata.startswith('10.'):
                           internal_ips += 1
                           print("[+] warning: internal IP address disclosed")

   except FileNotFoundError:
       print("Wordlist file not found.")
       return {}
   except Exception as e:
       print("An error occurred:", str(e))
       return {}

   end_time = time.time()  # Record end time
   completion_time = int(end_time - start_time)  # Calculate completion time

   print(f"\n[+] {total_domains} (sub)domains and {total_ips} IP address(es) found")
   if (internal_ips > 0):
       print(f"[+] {internal_ips} internal IP address(es) disclosed")
   print(f"[+] completion time: {completion_time} second(s)")


# Function to perform WHOIS lookup
def WHO_IS(domain):
   try:
       whois_domain = get_whois_server(domain)
       ip_addresses = socket.gethostbyname_ex(whois_domain)[2]

       for ip in ip_addresses:
           whois_query = (
                   domain + "\r\n"
           ).encode()

           sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           sock.connect((ip, WHOIS_PORT))

           sock.sendall(whois_query)

           sniff(prn=sniff_response, timeout=3)

           sock.close()

   except Exception as e:
       print("An error occurred:", e)


# Main function to handle user input
# Main function to handle user input
def main():
    while True:
        domain = input("\nEnter the command you would like to do (or type EXIT): ").lower()
        if domain == "exit":
            print("Exiting the program.")
            break
        prompt = domain.split(" ")
        if len(prompt) > 1 or len(prompt)  == 3:
            domain = prompt[1]
            if is_valid_domain(domain):
                if prompt[0] == "dig" and len(prompt) == 3 and prompt[2] == "caa":
                    record = CAA(domain)
                    if record:
                        print(f"CAA records for {domain}:")
                        for r in record:
                            print(record)

                elif len(prompt) == 2 and prompt[0] == "dnsmap":
                        DNS_MAP(domain)
                elif len(prompt) == 2 and prompt[0] == "whois":
                        WHO_IS(domain)
                elif len(prompt) == 2 and prompt[0] == "dnstoolkit.py":
                        domain = prompt[1]
                        if CAA(domain) == -1: #not connecting to server
                            break
                        DNS_MAP(domain)
                        WHO_IS(domain)

                else:
                    print("invalid input")

            else:
                print("invalid input")
        else:
            print("invalid input")


if __name__ == "__main__":
    main()

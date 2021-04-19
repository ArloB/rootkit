import socket, struct
from sys import argv

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error as msg:
    print(msg)
    exit(1)

try:
    f = open(argv[1], 'a+')
except:
    exit(2)

while True:
    packet = s.recvfrom(65565)
        
    packet = packet[0]
        
    iph = struct.unpack("!BBHHHBBH4s4s", packet[0:20])

    iph_length = (iph[0] & 0xF) * 4

    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
    
    tcph = struct.unpack("!HHLLBBHHH", packet[iph_length:iph_length+20])
    
    s_port = tcph[0]
    d_port = tcph[1]
    seq = tcph[2]
    ack = tcph[3]
    
    tcph_length = tcph[4] >> 4
    
    header_size = iph_length + tcph_length * 4

    data = packet[header_size:]

    data = data.decode(errors="ignore").replace('\n', '\n{0}'.format(' ' * 8))

    if len(data) > 0:
        f.write(f'Source: {s_addr}:{s_port} Destination: {d_addr}:{d_port} Seq#: {seq} Ack#: {ack}\n')
        
        f.write(f"Data: {data}\n")
        f.write(f"\n\n{'-' * 80}\n")


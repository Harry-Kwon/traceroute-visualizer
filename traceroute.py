import socket

def _create_sender(ttl):
    """creates a UDP socket with a set time-to-live value

    Args:
        ttl (int): the time-to-live of packets sent from this socket

    Returns:
        socket.socket: a udp socket object with the IP_TTL value set to ttl
    """
    sock = socket.socket(socket.AF_INET,
                         socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    return sock

def _create_receiver(port, timeout=10.0):
    sock = socket.socket(
        family=socket.AF_INET,
        type=socket.SOCK_RAW,
        proto=socket.IPPROTO_ICMP
    )

    try:
        sock.bind(('', port))
    except socket.error as error:
        raise IOError(f"Error binding receiver socket to {port}: {error}")
    
    sock.settimeout(timeout)
    
    return sock

def traceroute(address, port=33434, max_ttl=30, max_tries=3, ):
    """Perform a traceroute to the specified address

    Args:
        address (str): Destination address
        port (int, optional): Destination port. Defaults to 33434.
        max_ttl (int, optional): Maximum time-to-live tried. Defaults to 30.
        max_tries (int, optional): Maxium tries per hop/ttl. Defaults to 3.
    
    Returns:
        a generator yielding the address at each hop
    """
    recv_buffer=1024
    for ttl in range(1, max_ttl+1):

        for tries in range(max_tries):
            # create sender socket
            sender_socket = _create_sender(ttl)
            # create receiver socket
            receiver_socket = _create_receiver(port)

            # send a udp packet
            sender_socket.sendto(b"", (address, port))
            addr = None
            try:
                # listen for a ICMP response
                data, addr= receiver_socket.recvfrom(1024)
            except socket.error as error:
                if tries==max_tries-1:
                    # no response after max_tries, keep going
                    continue
                    #raise IOError(f"Error receiving from receiver socket: {error}")
            finally:
                sender_socket.close()
                receiver_socket.close()

            # yield the address if not null
        yield(addr)

        

if __name__ == "__main__":
    import sys

    max_hops = 30
    traceroute_generator = traceroute(sys.argv[1], max_ttl=max_hops)
    for i in range(max_hops):
        print(f"{i}: {next(traceroute_generator)}")
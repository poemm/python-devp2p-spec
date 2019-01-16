# Copyright 2018 Paul Dworzanski
# TODO: choose and open source license

# This is the discovery listener loop.
# ref: https://github.com/ethereum/devp2p/blob/master/discv4.md
def discovery_loop(shutdown_, debug_):

  # create socket to listen for messages
  s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )        # AF_INET: IPv4, SOCK_DGRAM: UDP 
  s.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )     # SO_REUSEADDR: can reuse port number without the OS making you wait
  s.bind( ('', myPORT_DISCOVERY) )                      # bind socket to port
  s.listen(max_connection_backog)       # listen with max number of messages to buffer befor dropping them

  # main loop
  while not shutdown:
    try:
      # listen for next connection
      message,address = sock.recvfrom(1280)

      # create thread to handle new discovery message
      #t = threading.Thread( target = handle_discovery_msg, args = [ sock, packet ] )
      #t.start()

      # break packet into parts
      packet_header = packet[:98]
      hash_ = packet_header[:32]
      signature = packet_header[32:97]
      packet_type = packet_header[98]
      packet_data = packet[98:]
  
      # verify signature
      # if signature != secp256k1_verify(packet_type+packet_data): return 0

      if packet_type == 1: # ping
        # decode packet_data
        version,from_,to,expiration = rlp_decode(packed_data)
        #if expiration < time(): return 0
        sender_ip, sender_udp_port, sender_tcp_port = from_
        recipient_ip, recipient_udp_port, _ = to

        # respond with pong
        #response_packet_data = rlp_encode(  )
        #sock.sendto(responce_packet_data,address)
      
      # consider the sender for addition into the node table

    except:
      if debug:
        traceback.print_exc()
        continue

  s.close()

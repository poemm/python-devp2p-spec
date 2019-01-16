
# Copyright 2018 Paul Dworzanski
# TODO: choose and open source license


import os
import RLP
rlp_decode = RLP.RLP
rlp_encode = RLP.RLP_inv
import crypto
import discovery


# Parameters
max_peers = 40
max_message_backlog = 40
listener_timeout_seconds = 60
shutdown = False
debug = 1 # debug levels: 0=none, 1=exceptions, 2=some more, 3=much more, 4=everything
myNodeID = ""
my_priv_key = None
myIP = ""
myPORT = 30303
myPORT_DISCOVERY = 30301
buffer_size = 2048		# read data at reasonable sized chunks
timeout_recv = 100.0		# seconds to wait before failing to receive data

# This node's capabilities and status
protocolVersion = 62 #PV62 of eth protocol
myCapabilities = [["eth",protocolVersion]]
networkID = 1	# 1 for mainnet
totalDifficulty = 0	# TODO: huh?
blocks = []
maxBlocks = 256


# Peer connection using RLPx
class PeerConnection:

  # class objects for peer management
  peers = {}			# key-value pairs: nodeID : instance of PeerConnection
  peers_ip_addresses = {}	# ip_address : list of nodeIDs at that ip address

  def __init__(self, ip_address, port, remote_pubk=None, sock = None, nodeID = None, send_hello=False):
    if debug==4: print("instantiating new peer connection with ip,port,sock", ip_address, port, sock)

    # socket stuff
    if not ip_address and not port and not sock:
      return None
    self.ip_address = ip_address
    self.port = port
    if sock:
      self.sock = sock
    else:
      self.sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
      self.sock.connect( ( self.ip_address, self.port ) )

    # connection managment stuff
    self.time_last_touched = time.time()
    self.alive = True
    self.capabilities = []
    self.message_handlers = {
      0 : self.recv_hello,
      1 : self.recv_disconnect,
      2 : self.recv_ping,
      3 : self.recv_pong,
      16 : self.recv_Status,
      17 : self.recv_NewBlockHashes,
      18 : self.recv_Transactions,
      19 : self.recv_GetBlockHashes,
      20 : self.recv_BlockHashes,
      21 : self.recv_GetBlocks,
      22 : self.recv_Blocks,
      23 : self.recv_NewBlock,
      24 : self.recv_BlockHashesFromNumber,
    }
    self.best_block_idx = 0


    # next are steps of the handshake
    # ref: handshake section of https://github.com/ethereum/devp2p/blob/master/rlpx.md
    #      also useful to read the wikipedia article for ECIES

    if remote_pubk:
      self.initiator=True
    else:
      self.initiator=False

    # 1. initiator connects to recipient and sends auth message
    if self.initiator:
      self.remote_pubk = remote_pubk
      self.static_shared_secret = crypt.ecdh_agree(my_priv_key, self.remote_pubk)
      initiator_nonce = os.urandom(32)
      static_shared_secret_xor_nonce = [ a ^ b for (a,b) in zip(self.static_shared_secret, initiator_nonce) ] 
      ephemeral_priv_key = crypto.generate_priv_key()
      ephemeral_pub_key = crypto.get_nodeid(ephemeral_priv_key)
      S = crypt.sign(ephemeral_privk, static_shared_secret_xor_nonce)
      H = crypto.keccak256(ephemeral_pub_key)
      # auth message: auth -> E(remote-pubk, S(ephemeral-privk, static-shared-secret ^ nonce) || H(ephemeral-pubk) || pubk || nonce || 0x0)
      #               static-shared-secret = ecdh.agree(privkey, remote-pubk)
      auth_plaintext = S + H + myNodeID + initiator_nonce + byte([0x00])

      # get various keys to encrypt the auth_plaintext with
      keys = crypto.KDF32(self.static_shared_secret)
      key_enc,key_mac = keys[:16],keys[16:]
      
      # encrypt message, need initialization vector for AES
      iv = os.urandom(16)
      auth_ciphertext = crypto.AES_encrypt(key_enc, iv, auth_plaintext)

      # compute the tag d of the ciphertext
      d = crypto.MAC(key_mac,iv+auth_ciphertext)

      # R || iv || c || d
      msg = ephemeral_pub_key + iv + auth_ciphertext + d

      # finally send
      self.socket.send(msg)

    # 2. recipient accepts, decrypts and verifies auth (checks that recovery of signature == keccak256(ephemeral-pubk))
    if not self.initiator: # recipient
      # receive message R || iv || c || d
      msg = self.socket.recv()

      # unpack message
      remote_ephemeral_pubk = msg[:64]
      iv = msg[64:]
      auth_ciphertext = msg[:]
      d = msg[:]

      # get plaintext of auth ciphertext
      self.static_shared_secret = crypto.ecdh_agree(my_priv_key, remote_ephemeral_pubk)
      keys = crypto.KDF32(self.static_shared_secret)
      key_enc,key_mac = keys[:16],keys[16:]
      # check authenticity
      if d != crypt.MAC(key_mac,iv+auth_ciphertext):
        return False #Error
      # decrypt
      auth_plaintext = crypto.AES_decrypt(key_enc, iv, auth_ciphertext)

      # unpack auth plaintext
      S = auth_plaintext[:]
      H = auth_plaintext[:]
      pubk = auth_plaintext[:]
      nonce = auth_plaintext[:]

    # 3. recipient generates auth-ack message from remote-ephemeral-pubk and nonce
    if not self.initiator: # recipient
      # generate auth_ack message: auth-ack -> E(remote-pubk, remote-ephemeral-pubk || nonce || 0x0)
      recipient_nonce = os.urandom(32)
      auth_ack_plaintext = remote_ephemeral_pubk + recipient_nonce + bytes([0x00])

      # encrypt auth_ack message
      auth_ack_ciphertext = crypto.AES_encrypt(key_enc, iv, auth_ack_plaintext)

      # finally send
      self.socket.send(auth_ack_ciphertext)

    # 4. recipient derives secrets and sends the first payload frame
    if not self.initiator: # recipient
      #ephemeral-shared-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
      ephemeral_shared_secret = crypto.ecdh_agree(ephemeral_privkey, remote_ephemeral_pubk)
      #shared-secret = keccak256(ephemeral-shared-secret || keccak256(nonce || initiator-nonce))
      self.shared_secret = crypto.keccak256(ephemeral_shared_secret + crypto.keccak256(recipient_nonce + initiator_nonce))
      #aes-secret = keccak256(ephemeral-shared-secret || shared-secret)
      self.aes_secret = crypto.keccak256(ephemeral_shared_secret + self.shared_secret)
      #mac-secret = keccak256(ephemeral-shared-secret || aes-secret)
      self.mac_secret = crypto.keccak256(ephemeral_shared_secret + self.aes_secret)
      #egress-mac = keccak256.update(mac-secret ^ recipient-nonce || auth-sent-init)
      self.egress_mac = crypto.keccak256([a^b for a,b in zip(self.mac_secret, recipient_nonce)] + self.auth_sent_init)
      #ingress-mac = keccak256.update(mac-secret ^ initiator-nonce || auth-recvd-ack)
      self.ingress_mac = crypto.keccak256([a^b for a,b in zip(self.mac_secret,initiator_nonce)] + self.auth_recvd_ack)

      # send first payload frame, hello
      self.send_hello()

    # 5. initiator receives auth-ack and derives secrets
    if self.initiator:
      # receive message auth_ack_ciphertext
      auth_ack_ciphertext = self.socket.recv()

      # decrypt
      auth_plaintext = crypto.AES_decrypt(key_enc, iv, auth_ack_ciphertext)
      
      # unpack   remote-ephemeral-pubk || nonce || 0x0
      remote_ephemeral_pubk = auth_plaintext[:]
      remote_nonce = auth_plaintext[:]

      #ephemeral-shared-secret = ecdh.agree(ephemeral-privkey, remote-ephemeral-pubk)
      ephemeral_shared_secret = crypto.ecdh_agree(ephemeral_privkey, remote_ephemeral_pubk)
      #shared-secret = keccak256(ephemeral-shared-secret || keccak256(nonce || initiator-nonce))
      self.shared_secret = crypto.keccak256(ephemeral_shared_secret + crypto.keccak256(recipient_nonce + initiator_nonce))
      #aes-secret = keccak256(ephemeral-shared-secret || shared-secret)
      self.aes_secret = crypto.keccak256(ephemeral_shared_secret + self.shared_secret)
      #mac-secret = keccak256(ephemeral-shared-secret || aes-secret)
      self.mac_secret = crypto.keccak256(ephemeral_shared_secret + self.aes_secret)
      #egress-mac = keccak256.update(mac-secret ^ recipient-nonce || auth-sent-init)
      self.egress_mac = crypto.keccak256([a^b for a,b in zip(self.mac_secret, recipient_nonce)] + self.auth_sent_init)
      #ingress-mac = keccak256.update(mac-secret ^ initiator-nonce || auth-recvd-ack)
      self.ingress_mac = crypto.keccak256([a^b for a,b in zip(self.mac_secret,initiator_nonce)] + self.auth_recvd_ack)

    # 6. initiator sends first payload frame
    if self.initiator:
      self.send_hello()

    # 7. recipient receives and authenticates first payload frame
    if not self.initiator: # recipient
      self.recv_hello()

    # 8. initiator receives and authenticates first payload frame
    if self.initiator:
      self.recv_hello()

    # 9. cryptographic handshake is complete if MAC of first payload frame is valid on both sides

    # now both can send status message for eth subprotocol
    self.send_Status()
    self.recv_Status()


  # Beginning of p2p sub-protocol senders and receivers
  # ref: https://github.com/ethereum/devp2p/blob/master/devp2p.md

  def recv_hello(self):
    # 0x00 [p2pVersion: P, clientId: B, [[cap1: B_3, capVersion1: P], [cap2: B_3, capVersion2: P], ...], listenPort: P, nodeId: B_64]
    if debug==4: print("recv_hello() ip:",self.ip_address)
    try:
      message_raw = self.recv_data_after_msgtype()
      message = rlp_decode(message_raw)
      if len(message) != 5:
        self.close(0x02)
        return False
      p2pVersion = message[0]
      clientId = message[1]
      capabilities = message[2]
      listenPort = message[3]
      nodeId = message[4]
      self.nodeID = nodeID
      self.capabilities = capabilities
      return True
    except:
      if debug: traceback.print_exc()
      return False

  def send_hello():
    if debug==4: print("send_hello() ip:",self.ip_address)
    p2pVersion = 1
    clientId = "Ethereum(++)/1.0.0"	#TODO
    cap = myCapabilities
    listenPort = myPORT
    nodeId = myNodeID
    message = rlp_encode([p2pVersion,clientId,cap,listenPort,nodeId])
    self.sock.send(0x00)
    self.sock.send(message)

  def recv_disconnect(self):
    # 0x01 [reason: P]
    # analyze message_raw, should be only one byte
    message_raw = self.recv_data_afer_msgtype()
    # disconnect
    self.alive = False

  def send_disconnect(self,reason):
    try:
      message = bytes([0x01,0x00])
      self.sock.send(message)
    except:
      if debug: traceback.print_exc()
      if debug: print("  network: error sending disconnect to peer at ip",self.ip_address)
    self.alive = False

  def recv_ping(self):
    # 0x02 []
    self.send_pong()

  def send_ping(self):
      self.send_frame([0x02])

  def recv_pong(self):
    # 0x03 []
    self.time_last_touched = time.time()

  def send_pong(self):
    try:
      self.sock.send(0x03)
    except:
      if debug:
        print("Error receiving message")
        traceback.print_exc()



  # Beginning of eth sub-protocol senders and receivers
  # ref: https://github.com/ethereum/wiki/wiki/Ethereum-Wire-Protocol

  def send_Status(self):
    # [+0x00: P, protocolVersion: P, networkId: P, td: P, bestHash: B_32, genesisHash: B_32]
    msg = [ self.capabilities.index("eth_Status"),
            protocolVersion,
            networkID,
            totalDifficulty,  #TODO: depends on state
            bestHash,         #TODO: depends on state
            genesisHash,      #TODO
     ]
    msg_raw = rlp_encode(myStatus)
    try:
      self.sock.send(msg_raw)
      self.flag_status_send = True
      return True
    except:
      if debug:
        print("Error receiving message")
        traceback.print_exc()
      return False

  def recv_Status(self):
    message_raw = self.recv_data_afer_msgtype()
    message = rlp_decode(message_raw)
    peer_protocolVersion, peer_networkID, peer_totalDifficulty, peer_bestHash, peer_genesisHash = message
    if peer_networkID != networkID:
      self.alive = 0
      return
    # The client with the worst TD asks peer for full chain of just block hashes.
    if peer_totalDifficulty > totalDifficulty:
      # ask for full chain of block hashes
      self.send_GetBlockHashes()
    
  def send_NewBlockHashes(self):
    # [+0x01: P, hash1: B_32, hash2: B_32, ...]
    pass

  def recv_NewBlockHashes(self):
    pass
    
  def send_Transactions(self, tx):
    # [+0x02: P, [nonce: P, receivingAddress: B_20, value: P, ...], ...] 
    pass

  def recv_Transactions(self):
    pass
    
  def send_GetBlockHashes(self):
    # [+0x03: P, hash : B_32, maxBlocks: P]
    pass

  def recv_GetBlockHashes(self):
    pass

  def send_BlockHashes(self):
    # [+0x04: P, hash_0: B_32, hash_1: B_32, ...]
    pass

  def recv_BlockHashes(self):
    pass

  def send_GetBlocks(self):
    # [+0x05: P, hash_0: B_32, hash_1: B_32, ...]
    pass

  def recv_GetBlocks(self):
    pass
    
  def send_Blocks(self):
    # [+0x06, [blockHeader, transactionList, uncleList], ...]
    pass

  def recv_Blocks(self):
    pass

  def send_NewBlock(self):
    # [+0x07, [blockHeader, transactionList, uncleList], totalDifficulty]
    pass

  def recv_NewBlock(self):
    pass

  def send_BlockHashesFromNumber(self,num):
    #[+0x08: P, number: P, maxBlocks: P] Requires peer to reply with a BlockHashes message. Message should contain block with that of number number on the canonical chain. Should also be followed by subsequent blocks, on the same chain, detailing a number of the first block hash and a total of hashes to be sent. Returned hash list must be ordered by block number in ascending order.
    msg = [ num, maxBlocks ]
    msg_raw = rlp_encode(msg)
    self.sock.send( self.capabilities.index("eth_BlockHashesFromNumber") + 8 )
    self.sock.send( msg_raw )

  def recv_BlockHashesFromNumber(self):
    message_raw = self.recv_data_afer_msgtype()
    message = rlp_decode(message_raw)
    if len(message) != 2:
      self.alive = 0
      self.close(0x02)
      return
    num, max_blocks_ = message
    # TODO: send back maxBlocks hashes starting from number

  def send_NewBlockHashes():
    # [+0x01: P, [hash_0: B_32, number_0: P], [hash_1: B_32, number_1: P], ...]
    pass

  def recv_NewBlockHashes():
    pass

  def send_GetBlockHeaders():
    # [+0x03: P, block: { P , B_32 }, maxHeaders: P, skip: P, reverse: P in { 0 , 1 } ]
    pass

  def recv_GetBlockHeaders():
    pass

  def send_BlockHeaders():
    #[+0x04, blockHeader_0, blockHeader_1, ...]
    pass

  def recv_BlockHeaders():
    pass

  def send_GetBlockBodies():
    # [+0x05, hash_0: B_32, hash_1: B_32, ...]
    pass

  def recv_GetBlockBodies():
    pass

  def send_BlockBodies():
    # [+0x06, [transactions_0, uncles_0] , ...]
    pass

  def recv_BlockBodies():
    pass


  # helper functions to send/receive framed messages, including encryption/decryption
  # ref: framing section of https://github.com/ethereum/devp2p/blob/master/rlpx.md
  # each frame has the following structure, which we will encode and decode
  """
    frame = header || header-mac || frame-data || frame-mac
    header = frame-size || header-data || padding
    frame-size = size of frame excluding padding, integer < 2**24, big endian
    header-data = rlp.list(protocol-type[, context-id])
    protocol-type = integer < 2**16, big endian
    context-id = integer < 2**16, big endian
    padding = zero-fill to 16-byte boundary
    frame-content = any binary data
    header-mac = left16(egress-mac.update(aes(mac-secret,egress-mac)) ^ header-ciphertext).digest
    frame-mac = left16(egress-mac.update(aes(mac-secret,egress-mac)) ^ left16(egress-mac.update(frame-ciphertext).digest))
    left16(x) is the first 16 bytes of x
    || is concatenate
    ^ is xor
  """

  def recv_frame( self ):

      # read the frame, based on frame size
      try:
        frame_size = self.sock.read(3)
        # read in chunks of length buffer_size, with timeout of timeout_recv seconds
        frame = bytearray(frame_size)
        for chunk_idx in range(0,int(frame_size),buffer_size):
          frame += bytearray( self.sock.recv( min(frame_size-chunk_idx,buffer_size) ) )
      except:
        if debug:
          print("Error receiving message")
          traceback.print_exc()
        self.close()
        return None
      # get length of rlp object, following rlp spec in yellowpaper
      rlp_length = 0
      first_rlp_byte = frame[3:4]
      if first_rlp_byte < 0x80:
        pass
      elif first_rlp_byte <= 0xb7:
        rlp_length = first_rlp_byte - 0x80
      elif first_byte <= 0xbf:
        length_length = first_rlp_byte - 0xb7
        lenstr = frame[4:length_length]
        rlp_length = int(struct.unpack( "!L", lenstr )[0])
      elif first_rlp_byte <= 0xf7: 
        rlp_length = first_rlp_byte - 0xc0 
      elif first_rlp_byte <= 0xbf:
        length_length = first_rlp_byte - 0xb7
        lenstr = frame[4:4+length_length]
        rlp_length = int(struct.unpack( "!L", lenstr )[0])
      # read rlp object
      header_data = rlp_decode(frame[3:])
      # read padding
      padding_length = (16 - (len(frame_size) + len(header_data)) % 16) % 16
      self.sock.recv( padding_length )
      # read header-mac
      header_mac_length = 16
      header_mac = self.sock.recv( header_mac_length )
      # read frame-data
      frame_start_idx = len(frame_size)+len(header_data)+padding_length+header_mac_length
      frame_data = frame[frame_start_idx:-16]
      # read frame-mac
      frame_mac = frame[-16:]

      # update egress_mac and ingress_mac
      # egress-mac = keccak256 state, continuously updated with egress bytes
      self.egress_mac = crypto.keccak256() #TODO
      # ingress-mac = keccak256 state, continuously updated with ingress bytes
      self.ingress_mac = crypto.keccak256() #TODO

      return header_data, frame_data


  def send_frame(protocol_type, frame_data):
    frame = bytearray([])
    header = bytearray([])
    header_data = rlp_encode([protocol_type])
    header_mac = # TODO
    frame_mac = # TODO
    padding_length = ( 16 - (3 + len(header_data)) % 16 ) % 16
    padding = bytearray([0x00]*padding_length)
    frame_size = 3 + len(header_data) + len(padding) + len(header_mac) + len(frame_data) + len(frame_mac)
    frame = bytearray([frame_size]) + header_data + padding + header_mac + frame_data + frame_mac
    self.sock.send(frame)



  # this main loop for this peer connection, waits for messages over this socket, and dispatches handlers

  def peer_connection_loop():
    # main loop for this connection
    while (not shutdown) and self.alive:
      header_data, frame_data = recv_frame()
      msgtype = frame_data[0]
      if msgtype not in self.handlers:
        if debug: print( "  network: don't know message type:",msgtype )
      else:
        if debug: print( "  network: Handling peer msgtype:",msgtype )
        self.handlers[ msgtype ]( frame_data )
      
    if debug: print( "  network: disconnecting peer", self.nodeID, clientsock.getpeername() )
    self.close(0x00)



  def close(self, reason=0x00):
    """
    reason is an optional integer specifying one of a number of reasons for disconnect:
      0x00 Disconnect requested;
      0x01 TCP sub-system error;
      0x02 Breach of protocol, e.g. a malformed message, bad RLP, incorrect magic number &c.;
      0x03 Useless peer;
      0x04 Too many peers;
      0x05 Already connected;
      0x06 Incompatible P2P protocol version;
      0x07 Null node identity received - this is automatically invalid;
      0x08 Client quitting;
      0x09 Unexpected identity (i.e. a different identity to a previous connection/what a trusted peer told us).
      0x0a Identity is the same as this node (i.e. connected to itself);
      0x0b Timeout on receiving a message (i.e. nothing received since sending last ping);
      0x10 Some other reason specific to a subprotocol.
    """
    self.send_disconnect(reason)
    self.sock.close()
    self.alive = 0




# this function creates a new peer connection, and starts the connection's loop which handles subsequent incoming messages
def handle_new_peer(socket, send_hello=False, nodeID = None):
  if debug:
    print( "  network: handling message from peer", clientsock.getpeername(), " on thread :", threading.currentThread().getName() )

  # TODO: check if we are already communicating with this node based on IP address (but what if there are multiple nodeIDs at an IP address, then need to send Hello to get their nodeID)

  if len(peers)<max_peers: # if we have room for more peers
    peer_connection = PeerConnection( ip_address, port, sock = socket, nodeID=nodeID send_hello=send_hello )
    peer_connection.peer_connection_loop()

  socket.close()



# this is the loop to listen for new peers
def new_peer_listener_loop():
  # create socket to listen for TCP messages
  s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )	# AF_INET: IPv4, SOCK_STREAM: TCP
  s.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )	# SO_REUSEADDR: can reuse port number without the OS making you wait
  s.bind( ('', myPORT) )			# bind socket to port
  s.listen(max_connection_backlog)	# listen with max number of messages to buffer befor dropping them

  # main loop to listen for new TCP connections (i.e. outside of existing peer connections)
  while not shutdown:
    try:
      # listen for next connection
      sock, ipaddr = s.accept()
      
      # create thread to handle new peer
      t = threading.Thread( target = handle_new_peer, args = [ sock ] )
      t.start()
    except:
      if debug:
        traceback.print_exc()
      continue



# thread to ping peers every hour
def heartbeat_loop():
  while not shutdown:
   for peer in PeerConnection.peers:
     if time.time() - peer.time_last_touched > 12*60*60: # 12 hours
       peer.close(0x00) # TODO: error message
     else:
       peer.send_ping()
   time.sleep( 3600 )




# MAIN FUNCTION
# creates threads for discovery, heartbeat, and incoming connections
# has a loop which communicates with the ethereum client, making sure blocks are downloaded
def main_p2p_loop(shutdown_, debug_, config, shared_data):

  debug = debug_
  shutdown = shutdown_

  if debug:
    # get my ip address
    s = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
    s.connect( ( "www.duckduckgo.com", 80 ) )
    myIP = s.getsockname()[0]
    s.close()
    print("starting new node at ip address: ", myIP, myPORT)

  # Create NodeID
  myNodeID = "" #TODO

  # connect to any specified enodes
  for enode in config["enodes"]:
    try:
      enode_sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )
      enode_sock.connect( ( enode["ip"], enode["port"] ) )
      t = threading.Thread( target = handle_new_peer, args = [ enode_sock ] )
      t.start()
    except:
      if debug: traceback.print_exc()
      if debug>2:  print("failed to connect to enode", enode)
      continue

  # create thread for handling discovery messages
  thread_discovery = threading.Thread( target = discovery.discovery_loop )
  thread_discovery.start()

  # create thread for handling discovery messages
  thread_discovery = threading.Thread( target = heartbeat_loop )
  thread_heartbeat.start()

  # create thread for handling peer messages
  thread_new_peer_listener_loop = threading.Thread( target = new_peer_listener_loop )
  thread_new_peer_listener_loop.start()

  # MAIN LOOP, communicates with the rest of the ethereum client, sends/receives transactions and blocks
  while not shutdown:
   # get newly downloaded blocks
   for peer in peers:
     if peer.new_blocks:
       shared_data["new_blocks_received"] += peer.new_blocks
       peer.new_blocks = []
   # get transactions from each peer
   for peer in peers:
     if peer.new_txs:
       shared_data["new_transactions_received"] += peer.new_txs
       peer.new_txs = []
   # send any new transactions to each peer
   if shared_data and shared_data["new_transactions_sent"]:
     for peer in peers:
       peer.send_Transactions(shared_data["new_transactions_sent"])
   # send block if you just mined one
   if shared_data and shared_data["new_blocks_sent"]:
     for peer in peers:
       for block in shared_data["new_blocks_sent"]
         peer.send_NewBlock(block)
   time.sleep( 0.01 )
     

  # done, block on joining threads
  thread_heartbeat_loop.join()
  thread_new_peer_listener_loop.join()
  #thread_discovery.join()
  for peer in PeerConnection.peers:
    peer.alive = False
    #peer.thread.join() #TODO
  s.close()








if __name__ == "__main__":
  # create hard-coded config
  config={}
  config["enodes"] = [ {"nodeID":"6f8a80d14311c39f35f516fa664deaaaa13e85b2f7493f37f6144d86991ec012937307647bd3b9a82abe2974e1407241d54947bbb39763a4cac9f77166ad92a0", "ip":"10.3.58.6", "port":30303, "discovery_port":30301} ]
  main_p2p_loop(0, 5, config)



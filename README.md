# python-devp2p-spec

This is a work-in-progress implementation of devp2p.

Design goal follow.
 (1) Clarity and readability, not performance.
 (2) Closely following the specifications. The code includes links to specific parts of the spec.
     - devp2p: https://github.com/ethereum/devp2p
     - ethereum subprotocol:  https://github.com/ethereum/wiki/wiki/Ethereum-Wire-Protocol
 (3) This Python code is for prototyping. Some prototypes and will be translated to compiled languages (like C/C++). Avoid "Pythonic" conventions, and libraries which are difficult to translate.

The architecture is as follows.
 - A PeerConnection class is instantiated for each socket connection to an ethereum peer.
   - Includes initialization handshakes, RLPx (multiplexed, encrypted) communication, message handlers.
   - A main loop to listen for messages over this peer connection.
 - No async event-loop, only threads. The main function starts the following threads.
    - A peer listener thread listens for new TCP connections from other peers, and starts a new thread for each new connection.
    - A discovery listener thread listens for new UDP messages, and handles them.

TODO:
[x] initial architecture described above
[x] initial code for RLPx
[x] initial code for p2p and eth subprotocol
[ ] RLPx complete
[ ] p2p and eth subprotocols complete
[ ] other subprotocols like les, shh, bzz
[ ] discovery
[ ] reputation for peers
[ ] JSON RPC



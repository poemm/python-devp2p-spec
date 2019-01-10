# python-devp2p-spec

This is a work-in-progress implementation of devp2p.

Design goal follow.
 (1) Clarity and readability, not performance.
 (2) Closely following the specifications. The code includes links to specific parts of the spec which it implements.
 (3) This Python code is for prototyping; some prototypes and will be translated to compiled languages (like C/C++/Go/Rust), so avoid "Pythonic" conventions, and libraries which are difficult to translate.

The architecture is as follows.
 - A PeerConnection class is instantiated for each socket connection to an ethereum peer.
   - Includes code for handshake, RLPx (multiplexed, encrypted) communication, message handlers.
   - A loop to listen for messages over this peer connection.
 - Thread-based architecture. (No async event-loop.)
    - The main thread with a loop to communicate with the ethereum client.
    - A thread for listening for new TCP connections from potential peers.
    - A thread for each peer connection.
    - A thread for listening for new discovery UDP messages, and handling them.
    - A thread for a "heartbeat" to ping peers once every 12 hours.

TODO:
- [x] initial architecture described above
- [x] initial code for RLPx
- [x] initial code for p2p and eth subprotocol
- [ ] RLPx complete
- [ ] p2p and eth subprotocols complete
- [ ] other subprotocols like les, shh, bzz
- [ ] discovery
- [ ] reputation for peers
- [ ] JSON RPC



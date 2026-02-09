# PYTUI Chat

A simple relay-based chat with a Node.js WebSocket server and a Python TUI client (Textual). Clients announce themselves, request chats, exchange public keys, and then send end-to-end encrypted messages.

## Files
- server.js: WebSocket relay server.
- client.py: Python Textual TUI client.

## Install

### Server
1. Install Node.js 18+.
2. Install dependencies:
   - npm install

### Client
1. Create a virtual environment (optional).
2. Install dependencies:
   - pip install -r requirements.txt

## Run

### Start server
- npm start

### Start client
- python client.py

## Client commands
- /list
- /chat [clientId]
- /accept [clientId]
- /msg [clientId] <text>
- /add <clientId> <nickname> [public_key]
- /remove [clientId]
- /quit

## Notes
- The server simply relays messages; encryption happens in the client.
- Public keys are exchanged after a chat is accepted.
- Contacts are stored locally in contacts.json.

import base64
import json
import queue
import random
import string
import threading
from pathlib import Path

import websocket
from nacl.public import PrivateKey, PublicKey, Box
from nacl.encoding import Base64Encoder
from nacl import utils
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Footer, Input, RichLog, ListView, ListItem, Static

SERVER_URL = "ws://localhost:8080"
CONTACTS_FILE = Path("contacts.json")


def generate_client_id():
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"clientid_{suffix}"


class ChatClient:
    def __init__(self, nickname, contacts_path: Path):
        self.client_id = generate_client_id()
        self.nickname = nickname
        self.ws = None
        self.inbox = queue.Queue()
        self.private_key = PrivateKey.generate()
        self.public_key_b64 = self.private_key.public_key.encode(encoder=Base64Encoder).decode()
        self.contacts_path = contacts_path
        self.contacts = self._load_contacts()
        self.pending_requests = set()

    def _load_contacts(self):
        if not self.contacts_path.exists():
            return {}
        try:
            data = json.loads(self.contacts_path.read_text())
        except Exception:
            return {}
        contacts = {}
        for client_id, info in data.items():
            nickname = info.get("nickname") or client_id
            public_key_b64 = info.get("public_key_b64")
            contact = {
                "nickname": nickname,
                "public_key_b64": public_key_b64,
                "public_key": None,
                "online": False,
            }
            if public_key_b64:
                try:
                    contact["public_key"] = PublicKey(public_key_b64, encoder=Base64Encoder)
                except Exception:
                    contact["public_key_b64"] = None
            contacts[client_id] = contact
        return contacts

    def _save_contacts(self):
        payload = {}
        for client_id, info in self.contacts.items():
            payload[client_id] = {
                "nickname": info.get("nickname") or client_id,
                "public_key_b64": info.get("public_key_b64"),
            }
        self.contacts_path.write_text(json.dumps(payload, indent=2))

    def update_contact(self, client_id, nickname=None, public_key_b64=None, online=None):
        contact = self.contacts.setdefault(client_id, {
            "nickname": client_id,
            "public_key_b64": None,
            "public_key": None,
            "online": False,
        })
        if nickname:
            contact["nickname"] = nickname
        if public_key_b64:
            contact["public_key_b64"] = public_key_b64
            try:
                contact["public_key"] = PublicKey(public_key_b64, encoder=Base64Encoder)
            except Exception:
                contact["public_key"] = None
                contact["public_key_b64"] = None
        if online is not None:
            contact["online"] = online
        self._save_contacts()

    def remove_contact(self, client_id):
        if client_id in self.contacts:
            self.contacts.pop(client_id)
            self._save_contacts()

    def connect(self):
        self.ws = websocket.WebSocketApp(
            SERVER_URL,
            on_open=self.on_open,
            on_message=self.on_message,
            on_close=self.on_close,
            on_error=self.on_error,
        )
        thread = threading.Thread(target=self.ws.run_forever, daemon=True)
        thread.start()

    def close(self):
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass

    def send(self, payload):
        if not self.ws:
            return
        try:
            self.ws.send(json.dumps(payload))
        except Exception:
            pass

    def on_open(self, _ws):
        self.send({
            "type": "hello",
            "clientId": self.client_id,
            "nickname": self.nickname,
        })

    def on_message(self, _ws, message):
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            return
        self.inbox.put(payload)

    def on_close(self, *_):
        self.inbox.put({"type": "system", "message": "Disconnected from server."})

    def on_error(self, _ws, error):
        self.inbox.put({"type": "system", "message": f"Error: {error}"})

    def handle_message(self, payload):
        messages = []
        msg_type = payload.get("type")

        if msg_type == "welcome":
            online = payload.get("online", [])
            for entry in online:
                self.update_contact(entry["clientId"], nickname=entry["nickname"], online=True)
            messages.append(f"You are {self.client_id} ({self.nickname})")
            messages.append("Type /help for commands.")
            return messages

        if msg_type == "presence":
            client_id = payload.get("clientId")
            nickname = payload.get("nickname")
            status = payload.get("status")
            online = status == "online"
            self.update_contact(client_id, nickname=nickname, online=online)
            messages.append(f"{nickname} ({client_id}) is {status}")
            return messages

        if msg_type == "list_response":
            online = payload.get("online", [])
            messages.append("Online clients:")
            for entry in online:
                messages.append(f"- {entry['clientId']} ({entry['nickname']})")
                self.update_contact(entry["clientId"], nickname=entry["nickname"], online=True)
            return messages

        if msg_type == "chat_request":
            sender = payload.get("from")
            nickname = payload.get("nickname", "unknown")
            self.pending_requests.add(sender)
            self.update_contact(sender, nickname=nickname)
            messages.append(f"Chat request from {nickname} ({sender}). Use /accept {sender} to accept.")
            return messages

        if msg_type == "chat_accept":
            sender = payload.get("from")
            messages.append(f"Chat accepted by {sender}. Exchanging public keys...")
            self.send({
                "type": "public_key",
                "from": self.client_id,
                "to": sender,
                "publicKey": self.public_key_b64,
            })
            return messages

        if msg_type == "public_key":
            sender = payload.get("from")
            public_key_b64 = payload.get("publicKey")
            if public_key_b64:
                self.update_contact(sender, public_key_b64=public_key_b64)
                messages.append(f"Public key received from {sender}. You can now send encrypted messages.")
            else:
                messages.append("Failed to decode public key.")
            return messages

        if msg_type == "encrypted":
            sender = payload.get("from")
            contact = self.contacts.get(sender)
            if not contact or not contact.get("public_key"):
                messages.append(f"Encrypted message from {sender} but no public key stored.")
                return messages
            nonce_b64 = payload.get("nonce")
            ciphertext_b64 = payload.get("ciphertext")
            try:
                nonce = base64.b64decode(nonce_b64)
                ciphertext = base64.b64decode(ciphertext_b64)
                box = Box(self.private_key, contact["public_key"])
                message = box.decrypt(ciphertext, nonce).decode()
                messages.append(f"{sender}: {message}")
            except Exception:
                messages.append("Failed to decrypt message.")
            return messages

        if msg_type == "error":
            messages.append(f"Server error: {payload.get('message')}")
            return messages

        if msg_type == "system":
            messages.append(payload.get("message"))
            return messages

        return messages

    def request_chat(self, target_id):
        peer = self.contacts.get(target_id)
        nickname = peer["nickname"] if peer else "unknown"
        self.send({
            "type": "chat_request",
            "from": self.client_id,
            "to": target_id,
            "nickname": self.nickname,
        })
        return f"Chat request sent to {nickname} ({target_id})."

    def accept_chat(self, target_id):
        if target_id not in self.pending_requests:
            return "No pending request from that client."
        self.pending_requests.discard(target_id)
        self.send({
            "type": "chat_accept",
            "from": self.client_id,
            "to": target_id,
        })
        self.send({
            "type": "public_key",
            "from": self.client_id,
            "to": target_id,
            "publicKey": self.public_key_b64,
        })
        return f"Accepted chat with {target_id}. Public key sent."

    def send_encrypted(self, target_id, message):
        contact = self.contacts.get(target_id)
        if not contact or not contact.get("public_key"):
            return "No public key for that client. Accept a chat first."
        box = Box(self.private_key, contact["public_key"])
        nonce = utils.random(Box.NONCE_SIZE)
        encrypted = box.encrypt(message.encode(), nonce)
        payload = {
            "type": "encrypted",
            "from": self.client_id,
            "to": target_id,
            "nonce": base64.b64encode(encrypted.nonce).decode(),
            "ciphertext": base64.b64encode(encrypted.ciphertext).decode(),
        }
        self.send(payload)
        return f"You -> {target_id}: {message}"


class ChatApp(App):
    CSS = """
    Screen {
        background: #0b0f14;
        color: #e6e6e6;
    }
    #sidebar {
        width: 40;
        background: #141a22;
        padding: 1 1;
        border-right: solid #2a3443;
    }
    #main {
        padding: 1 1;
    }
    #contacts-title {
        height: 1;
        color: #c9d1d9;
    }
    #contacts-list {
        height: 1fr;
        background: #0f1620;
        border: solid #2a3443;
    }
    #status {
        height: 3;
        color: #9aa4b2;
    }
    #log {
        height: 1fr;
        background: #0e141b;
        border: solid #2a3443;
    }
    #input {
        margin-top: 1;
        background: #111923;
        border: solid #2a3443;
    }
    """

    def __init__(self, client: ChatClient):
        super().__init__()
        self.client = client
        self.selected_contact_id = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal():
            with Vertical(id="sidebar"):
                yield Static("Contacts", id="contacts-title")
                yield ListView(id="contacts-list")
                yield Static("", id="status")
            with Vertical(id="main"):
                yield RichLog(id="log", wrap=True, markup=False)
                yield Input(placeholder="Type /help for commands", id="input")
        yield Footer()

    def on_mount(self):
        self.refresh_contacts()
        self.set_interval(0.1, self.poll_inbox)
        self.query_one(Input).focus()
        self.log_line("Connecting to server...")

    def on_unmount(self):
        self.client.close()

    def poll_inbox(self):
        updated = False
        while not self.client.inbox.empty():
            payload = self.client.inbox.get()
            lines = self.client.handle_message(payload)
            for line in lines:
                self.log_line(line)
            updated = True
        if updated:
            self.refresh_contacts()

    def log_line(self, message):
        self.query_one(RichLog).write(message)

    def update_status(self, message):
        self.query_one("#status", Static).update(message)

    def refresh_contacts(self):
        list_view = self.query_one(ListView)
        list_view.clear()
        for client_id, info in sorted(self.client.contacts.items()):
            nickname = info.get("nickname") or client_id
            status = "online" if info.get("online") else "offline"
            key_flag = "key" if info.get("public_key") else "nokey"
            label = f"{nickname} ({client_id}) [{status}, {key_flag}]"
            list_view.append(ListItem(Static(label), name=client_id))
        if self.selected_contact_id:
            self.update_status(f"Selected: {self.selected_contact_id}")

    def on_list_view_highlighted(self, event: ListView.Highlighted):
        if event.item:
            self.selected_contact_id = event.item.name
            self.update_status(f"Selected: {self.selected_contact_id}")

    def on_input_submitted(self, event: Input.Submitted):
        line = event.value.strip()
        event.input.value = ""
        if not line:
            return
        if not line.startswith("/"):
            if self.selected_contact_id:
                response = self.client.send_encrypted(self.selected_contact_id, line)
                self.log_line(response)
            else:
                self.log_line("Select a contact or use /msg <id> <text>.")
            return
        self.handle_command(line)

    def handle_command(self, line):
        if line == "/quit":
            self.exit()
            return
        if line == "/help":
            self.log_line(
                "Commands: /list, /chat [id], /accept [id], /msg [id] <text>, /add <id> <nickname> [pubkey], /remove <id>, /quit"
            )
            return
        if line == "/list":
            self.client.send({"type": "list_request"})
            return
        if line.startswith("/chat"):
            parts = line.split(" ", 1)
            target_id = parts[1].strip() if len(parts) > 1 else self.selected_contact_id
            if not target_id:
                self.log_line("Usage: /chat <id> (or select a contact)")
                return
            self.log_line(self.client.request_chat(target_id))
            return
        if line.startswith("/accept"):
            parts = line.split(" ", 1)
            target_id = parts[1].strip() if len(parts) > 1 else self.selected_contact_id
            if not target_id:
                self.log_line("Usage: /accept <id> (or select a contact)")
                return
            self.log_line(self.client.accept_chat(target_id))
            return
        if line.startswith("/msg"):
            parts = line.split(" ", 2)
            if len(parts) >= 3:
                target_id = parts[1].strip()
                message = parts[2].strip()
            elif len(parts) == 2 and self.selected_contact_id:
                target_id = self.selected_contact_id
                message = parts[1].strip()
            else:
                self.log_line("Usage: /msg <id> <text> (or select a contact)")
                return
            self.log_line(self.client.send_encrypted(target_id, message))
            return
        if line.startswith("/add"):
            parts = line.split(" ", 3)
            if len(parts) < 3:
                self.log_line("Usage: /add <id> <nickname> [pubkey]")
                return
            target_id = parts[1].strip()
            nickname = parts[2].strip()
            pubkey = parts[3].strip() if len(parts) > 3 else None
            if pubkey:
                self.client.update_contact(target_id, nickname=nickname, public_key_b64=pubkey)
            else:
                self.client.update_contact(target_id, nickname=nickname)
            self.refresh_contacts()
            self.log_line(f"Contact saved: {nickname} ({target_id})")
            return
        if line.startswith("/remove"):
            parts = line.split(" ", 1)
            target_id = parts[1].strip() if len(parts) > 1 else self.selected_contact_id
            if not target_id:
                self.log_line("Usage: /remove <id> (or select a contact)")
                return
            self.client.remove_contact(target_id)
            if self.selected_contact_id == target_id:
                self.selected_contact_id = None
            self.refresh_contacts()
            self.log_line(f"Contact removed: {target_id}")
            return
        self.log_line("Unknown command. Use /help.")


def main():
    nickname = input("Enter nickname: ").strip() or "anon"
    client = ChatClient(nickname, CONTACTS_FILE)
    client.connect()
    app = ChatApp(client)
    app.run()


if __name__ == "__main__":
    main()

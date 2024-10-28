import json
import os
import socket
import threading
import time

from socket import setdefaulttimeout
from loguru import logger

setdefaulttimeout(5)

class Manager:

    def __init__(self, socket_file):
        self.run = False
        if os.path.exists(socket_file):
            os.unlink(socket_file)
        self.socket_file = socket_file
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.callbacks = []
        self.update_list = {"dhcp": [], "manager": []}
        self.thread = None

    def _start(self):
        self.run = True
        self.socket.bind(self.socket_file)
        self.socket.listen(10)
        logger.success(f"[manager] Listening on {self.socket_file}")
        while self.run:
            try:
                client_socket, _ = self.socket.accept()
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()
            except TimeoutError:
                pass
            except Exception as e:
                logger.exception(e)

    @staticmethod
    def _send(_sock, data):
        if not isinstance(data, bytes):
            data = json.dumps(data).encode()
        header = len(data).to_bytes(4, "little", signed=True)
        _sock.send(header + data)

    def handle_client(self, _sock):
        try:
            while self.run:
                # read size of the message
                raw_header = _sock.recv(4)
                header = int.from_bytes(raw_header, byteorder='little', signed=True)
                if header <= 0:
                    break
                # read the message data
                raw_data = b""
                while len(raw_data) < header:
                    buffer = _sock.recv(header - len(raw_data))
                    if not buffer:
                        break
                    else:
                        raw_data += buffer
                if not raw_data or (len(raw_data) < header):
                    self._send(_sock, {"error_code": 2})
                    break

                data_from, data_body = raw_data.split(b":", 1)
                data_from = data_from.decode().strip()
                if data_from not in self.update_list.keys():
                    self._send(_sock, {"error_code": 1})
                    break

                if data_body == b"ping":
                    self._send(_sock, b"pong")
                    continue

                data = json.loads(data_body)
                if data.get("act") == "callback":
                    try:
                        [callback(data_from, data) for callback in self.callbacks]
                    except Exception as e:
                        logger.error("Error in callback:")
                        logger.exception(e)
                elif data.get("act") == "get_update":
                    self._send(_sock, self.update_list[data_from])
                    self.update_list[data_from] = []
        except Exception as e:
            logger.exception(e)
        finally:
            _sock.close()

    def update(self, to, data):
        self.update_list[to].append(data)

    def start(self):
        self.thread = threading.Thread(target=self._start)
        self.thread.start()

    def stop(self):
        if self.run:
            self.run = False
            time.sleep(5.01)
            self.socket.close()
            if os.path.exists(self.socket_file):
                os.unlink(self.socket_file)
            logger.success("[manager] Stopped")

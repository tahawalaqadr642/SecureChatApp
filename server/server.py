import socket, threading
clients = []
def broadcast(message, source):
    for client in clients:
        if client != source:
            try:
                client.send(message)
            except:
                clients.remove(client)
def handle_client(client_socket):
    while True:
        try:
            msg = client_socket.recv(4096)
            if not msg:
                break
            broadcast(msg, client_socket)
        except:
            break
    clients.remove(client_socket)
    client_socket.close()
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 9999))
server.listen(5)
print("[+] Server started on port 9999")
while True:
    client_sock, addr = server.accept()
    print(f"[+] New connection from {addr}")
    clients.append(client_sock)
    threading.Thread(target=handle_client, args=(client_sock,)).start()

import socketserver
import he_placeholder
import os
import sys
from client import HardenedEncryption as HE # server.py is in the same folder as client.py inside the container


class MyTCPHandler(socketserver.BaseRequestHandler):    
    
    def handle(self):
        global action, policy, message, cnt, gid, attrs, wating_for_message, he
        if(action != None and policy != None and message != None):
            action, policy, message = None, None, None
            cnt+=1

        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(2048).strip()
        print("{} wrote:".format(self.client_address[0]))
        print(self.data)
        doThis()


        if(wating_for_message):
            wating_for_message = False
            message = self.data
            filename = "input_data"
            result_file = ""
            in_args = None
            
            with open(filename, "wb") as f:
                print("write file")
                f.write(message)
                            
                
            if(action == "encrypt"):
                
                in_args = (action, filename, policy)
                # TODO Do the encryption
                he.encryptFile(filename, policy)
                he_placeholder.encrypt(filename, policy)
                result_file = filename + ".enc"
                with open(result_file, mode='rb') as file:
                    print(file.read())
                action, policy, message = None, None, None
            if(action == "decrypt"):
                
                in_args = (action, filename)
                # TODO Do the encryption
                he.decryptFile(filename)
                result_file = filename + ".dec"
                he_placeholder.decrypt(filename)
                with open(result_file, mode='rb') as file:
                    print(file.read())
                action, policy, message = None, None, None
            #self.request.sendall(result)
            self.request.sendall(bytes(str(in_args), 'utf-8'))
            os.remove(filename)
            os.remove(result_file)
            # first message with instructions and second with the message (if needed)
        elif(action == None and not wating_for_message):
            data_str = self.data.decode()
            data_str = data_str.split(";")
            print("Data split:")
            print(data_str)
            action = data_str[0].strip()
            print(f"\tAction is {action}")
            if(action == "register"):
                wating_for_message = False # just to make sure...
                gid = data_str[1].strip()
                attribs = data_str[2].strip()
                # TODO Do the register
                he.register(gid, attribs)
                in_args = (action, gid, attrs)
                he_placeholder.register(gid, attrs)
                self.request.sendall(bytes("Successful Registration: "+str(in_args), 'utf-8'))
                action, policy, message = None, None, None
            elif(action == "encrypt"):
                policy = data_str[1].strip()
                print(f"Policy is {policy}")
                wating_for_message = True
            elif(action == "decrypt"):
                wating_for_message = True
        
        data_str = None
        print("\n\n")

def doThis():
    print("\nAction -> ", end="")
    print(cnt, action)
    print("Policy -> ", end="")
    print(cnt, policy)
    print("Message -> ", end="")
    print(cnt, message)
    print("\n")


if __name__ == "__main__":
    global action, policy, message, cnt, gid, attrs, wating_for_message, he
    cnt = 0
    wating_for_message = False
    action, policy, message, gid, attrs = None, None, None, None, None
    HOST, PORT = "0.0.0.0", 1245
    he = HE()
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()
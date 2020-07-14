
import collections
import hashlib
import json
import signal
import sys
import ssl
import uuid


from SimpleWebSocketServer import User, UserDatabase
from SimpleWebSocketServer import WebSocket, SimpleWebSocketServer
from optparse import OptionParser



class MyServer(WebSocket):


   def getUsername(self,cerdentials):
      return list(cerdentials.keys())[0]

   def getPassword(self, cerdentials):
      return list(cerdentials.values())[0]


   def generate_Salt(self):
      # uuid is used to generate a random number
      salt = uuid.uuid4().hex
      return salt

   def hash_password(self, password, salt):
      # uuid is used to generate a random number
      #salt = uuid.uuid4().hex
      return hashlib.sha256(salt.encode() + password.encode()).hexdigest() #+ ':' + salt

   #login/register{username:$username, password:$password}
   def handleMessage(self):
      print("client sent message: "+self.data)
      if (self.data[:3] == 'get'):
         print("user asked for data")
         u=self.getActiveUser()
         info=self.server.database.getInfo(u)
         self.sendMessage("info"+ info)
      if (self.data[:4] == 'save'):
         self.info = self.data[4:]
         self.server.database.saveInfo(self.getActiveUser(), self.data[4:])
         print("saved data")
         self.sendMessage("saved")
      if (self.data[:5]=='login'):
         cerdentials=json.loads(self.data[5:])
         if(self.checkLogin(cerdentials)):
               self.setActiveUser(self.getUsername(cerdentials))
               self.sendMessage("approve")
         else:
            print("denied")
            self.sendMessage("denied")
      elif(self.data[:8]=='register'):
            cerdentials = json.loads(self.data[8:])
            self.register(cerdentials)

      #self.sendMessage(self.hash_password("password"))

   def handleConnected(self):
      print("client connected")
      pass

   def handleClose(self):
      print("client DISCONNECTED")
      pass


   def checkLogin(self, cerdentials):
      username = self.getUsername(cerdentials)
      password = self.getPassword(cerdentials)
      if (self.server.database.searchUsername(self.getUsername(cerdentials))):
         salt=self.server.database.getSalt(username)
         #print(salt)
         return (self.server.database.checkLogin(username,self.hash_password(password,salt)))
      else:
         #self.server.database.addUser(user)
         self.sendMessage("username doesnt exist")
         print("username doesnt exist")

   def register(self,cerdentials):
      salt=self.generate_Salt()
      user = User(self.getUsername(cerdentials),self.hash_password(self.getPassword(cerdentials),salt),
                   salt,"")
     #print(user.__str__())
      if(self.server.database.searchUsername(self.getUsername(cerdentials))):
         self.sendMessage("Username already exist")
         print("Username already exist")
      else:
         self.server.database.addUser(user)
         self.sendMessage("register OK")
         print("added user")



if __name__ == "__main__":

   parser = OptionParser(usage="usage: %prog [options]", version="%prog 1.0")
   parser.add_option("--host", default='', type='string', action="store", dest="host", help="hostname (localhost)")
   parser.add_option("--port", default=8000, type='int', action="store", dest="port", help="port (8000)")
   parser.add_option("--example", default='echo', type='string', action="store", dest="example", help="echo, chat")
   parser.add_option("--ssl", default=0, type='int', action="store", dest="ssl", help="ssl (1: on, 0: off (default))")
   parser.add_option("--cert", default='./cert.pem', type='string', action="store", dest="cert", help="cert (./cert.pem)")
   parser.add_option("--key", default='./key.pem', type='string', action="store", dest="key", help="key (./key.pem)")
   parser.add_option("--ver", default=ssl.PROTOCOL_TLSv1, type=int, action="store", dest="ver", help="ssl version")

   (options, args) = parser.parse_args()

   cls = MyServer
   server = SimpleWebSocketServer("127.0.0.1", options.port, cls)



   def close_sig_handler(signal, frame):
      server.close()
      sys.exit()

   signal.signal(signal.SIGINT, close_sig_handler)

   server.serveforever()

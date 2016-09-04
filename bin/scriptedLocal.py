from __future__ import print_function

import sys
import logging
import ConfigParser
from commonAuth import *
from passlib.hash import sha512_crypt
from yubico_client import Yubico




#method for reading config
Config = ConfigParser.ConfigParser()
Config.read ('../etc/yubiauth.conf')

#config function
def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1



##########################
# some configuration stuff
###########################
yubicloud_client_id = ConfigSectionMap("yubikeySettings")['yubicloud_client_id']
yubicloud_secret_key= ConfigSectionMap("yubikeySettings")['yubicloud_secret_key']
passwdFile = ConfigSectionMap("globalSettings")['passwd']

logging.basicConfig()
logger=logging.getLogger()
logger.setLevel(logging.INFO)

# Disable some annoying SSL errors due to our python version
# Not the best solution, needs love
#import requests.packages.urllib3
#requests.packages.urllib3.disable_warnings()

def logit(msg):
   logger.info(msg)

# Dumb implementation of a passwd file
#<unused>:<username>:<hash>:<unused>:<realname>:<roles>:<email>:<unused>:<unused>:<unused>:<yubikeyid>
class PasswdFile:
	
   # wrapper to deal with missing fields
   def cleanget(self,list,element):
      try:
         return list[element]
      except IndexError:
         return None

 
   def __init__(self, file):
      self.users = { }
      f=open(file,"rt")
      for l in f:
         fields=l.strip().split(':')
         self.users[fields[1]] = { }
         self.users[fields[1]]['hash']=self.cleanget(fields,2)
         self.users[fields[1]]['realname']=self.cleanget(fields,4)
         self.users[fields[1]]['roles']=[]
         self.users[fields[1]]['roles'].extend(self.cleanget(fields,5).split(';'))
         self.users[fields[1]]['email']=self.cleanget(fields,6)
         self.users[fields[1]]['yubikeyid']=self.cleanget(fields,9)

p = None

def makeUserInfo(u,r):
    return ' --userInfo=;%s;%s;%s' % (u,r['realname'],':'.join(r['roles']))


def userLogin( args ):
    user=args[USERNAME]
    
    # Yubikey OTP is 44-characters so if there's not at least 45 chars then
    # we assume there's only a single factor and fail them out of spite 
    # also fail out of spite if the user does not have a yubikey in their password entry
    if user not in p.users:
       print(FAILED)
       logit("User not in table")
       return
  
    if (len(args['password']) < 45):
       print(FAILED)
       logit("Password too short to have yubi token")
       return

    if p.users[user]['yubikeyid'] is None:
       print(FAILED)
       logit("User has no yubi token in the passwd file")
       return

    # Otherwise split the first and second factors apart
    password=args['password'][0:-44]
    yubiotp=args['password'][-44:]

    userobject=p.users[user]
    
    # Check the first factor against the hash
    if not sha512_crypt.verify(password,userobject['hash']):
       print(FAILED)
       logit("First factor failed")
       return

    
     # does the yubikey belong to this user?
     # We should have pretty good assurance at this point that the userobject has a yubikeyid
     # value.  Our check above should have promised that
    if yubiotp[0:12] != userobject['yubikeyid']:
        print(FAILED)
        logit("Yubi token presented %s does not match what is on file %s" % (yubiotp[0:12],userobject['yubikeyid']))
        return
        
    try:
        # Now FINALLY we go to yubicloud and ask
        yubi = Yubico(yubicloud_client_id,yubicloud_secret_key)
        if yubi.verify(yubiotp):
            print(SUCCESS)
            return
    except Exception as e:
         logging.error("Exception in yubi verify",e)
         print(FAILED)
         return

    # If we fall all the way out
    logit("Fell out the bottom")
    print(FAILED)


def getUserInfo( args ):
    # Use the same name for userId (deprecated), username, realname
    un = args[USERNAME]
    if un in p.users:
        print (SUCCESS + makeUserInfo(un,p.users[un]))
    else:
        print (FAILED)

def getUsers( args ):
    out = SUCCESS
    for u, r in p.users.iteritems():
	out = out + makeUserInfo(u,r)
    
    print (out)

def getSearchFilter( args ):
    # Ignore search filters
    if args[USERNAME] in p:
        print (SUCCESS)
    else:
        print (FAILED)

if __name__ == "__main__":

    p = PasswdFile('passwdFile')

    callName = sys.argv[1]
    dictIn = readInputs()

    returnDict = {}
    if callName == "userLogin":
        userLogin( dictIn )
    elif callName == "getUsers":
        getUsers( dictIn )
    elif callName == "getUserInfo":
        getUserInfo( dictIn )
    elif callName == "getSearchFilter":
        getSearchFilter( dictIn )
    else:
        print ("ERROR unknown function call: " + callName)

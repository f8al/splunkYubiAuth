#!/usr/bin/python

import base64
import sys
from Crypto.Cipher import AES                                                                                                                                                                        
q=open('../../../auth/splunk.secret').read()                                                                                                                                                         
key=q[0:16]                                                                                                                                                                                          
iv=q[17:33]                                                                                                                                                                                          

xxx=AES.new(key,AES.MODE_CFB,iv)                                                                                                                                                                     
cipher=base64.b64encode(xxx.encrypt(sys.argv[1]))
print cipher


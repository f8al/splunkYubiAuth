import base64
from Crypto.Cipher import AES                                                                                                                                                                        
q=open('../../../auth/splunk.secret').read()                                                                                                                                                         
key=q[0:16]                                                                                                                                                                                          
iv=q[17:33]                                                                                                                                                                                          

xxx=AES.new(key,AES.MODE_CFB,iv)                                                                                                                                                                     
cipher=base64.b64encode(xxx.encrypt('abc123'))

print repr(cipher)

xxx=AES.new(key,AES.MODE_CFB,iv)                                                                                                                                                                     
clear=xxx.decrypt(base64.b64decode(cipher))
print repr(clear)

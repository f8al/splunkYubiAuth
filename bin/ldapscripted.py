from __future__ import print_function

# import class and constants
import ConfigParser
import sys
import logging
import ldap3
import ldap3.utils.log 
import pprint
import itertools
import more_itertools
import warnings
import codecs
import ssl
import base64
import collections
from pyrad.dictionary import Dictionary

# We know yubico_client pulls in requests which pulls in cryptography, so
# grab it first with deprecationwarnings disabled
with warnings.catch_warnings():
    warnings.filterwarnings("ignore",category=DeprecationWarning)
    import cryptography


from commonAuth import *
#from yubico_client import Yubico
from Crypto.Cipher import AES

#load configuration file
Config = ConfigParser.ConfigParser()
Config.read("./etc/yubiauth.conf")

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


# Lame, but beats nothing
def decryptString(string):

    q=open('../../../auth/splunk.secret').read()
    key=q[0:16]
    iv=q[17:33]

    xxx=AES.new(key,AES.MODE_CFB,iv)
    return(xxx.decrypt(base64.b64decode((string))))

#----------------------------------------------------------------------------
# Some configuration stuff
#----------------------------------------------------------------------------


    ldap_servers = configSectionMap('ldapSettings')['ldap_servers']

    # Options to enable/disable certificate verification
    # Should be ssl.CERT_NONE or ssl.CERT_REQUIRED
    ldap_cert_verification = ssl.CERT_NONE
    ldap_certs_file = configSectionMap('ldapSettings')['ldap_certs_file']

    group_base_dn = configSectionMap('ldapSettings')['group_base_dn']
    user_base_dn = configSectionMap('ldapSettings')['user_base_dn']
    service_account_user = configSectionMap('ldapSettings')['SA_User']
    service_account_pass = configSectionMap('ldapSettings')['SA_Pass']

    ## These keys, if defined, work for everyone
    testing_yubikeys = ConfigSectionMap("yubikeySettings")['testKeys']

    # These users, if defined, skip the LDAP bind 1st factor
    # This is obviously HORRIBLY INSECURE
    skip_first_factor_users = ConfigSectionMap("globalSettings")['skip_auth_users']



#----------------------
# Group to role mapping
#----------------------

groups_to_roles = {

   'splunk_user_dl' = ConfigSectionMap("ldapSettings")['splunk_user_dl'] : ['user'],
   'splunk_admin_dl' = ConfigSectionMap("ldapSettings")['splunk_admin_dl'] : ['admin','user']
}


defaultloglevel=logging.INFO
requestsloglevel=logging.ERROR
ldap3_log_level=ldap3.utils.log.ERROR

#----------------------------------------------------------------------------
# End configuration stuff
#----------------------------------------------------------------------------

logging.basicConfig()
logger=logging.getLogger()
logger.setLevel(defaultloglevel)
ldap3.utils.log.set_library_log_detail_level(ldap3_log_level)

# dumb hack to deal with requests module logging stuff we are not concerned with
logging.getLogger('requests').setLevel(requestsloglevel)



# Stupid little hack for ldap3 when being used to output to a pipe
if ldap3.utils.repr.repr_encoding is None:
    ldap3.utils.repr.repr_encoding = 'UTF-8'

#----------------------------------------------------------------------------------
# Utility to help flatten lists
#----------------------------------------------------------------------------------
def flatten(l):
    for el in l:
        if isinstance(el, collections.Iterable) and not isinstance(el, basestring):
            for sub in flatten(el):
                yield sub
        else:
            yield el

#----------------------------------------------------------------------------------
# Simple factory for LDAP connections
#----------------------------------------------------------------------------------
def ldapConnectionFactory():
    tls = ldap3.Tls(validate=ldap_cert_verification, version=ssl.PROTOCOL_TLSv1, ca_certs_file=ldap_certs_file)
    server = ldap3.ServerPool(None, ldap3.POOLING_STRATEGY_ROUND_ROBIN, active=True, exhaust=True)
    for q in ldap_servers:
        x=ldap3.Server(q, tls=tls)
        server.add(x)

    conn = ldap3.Connection(server, service_account_user, service_account_pass, check_names=True)
    conn.bind()
    return conn


#---------------------------------------------------------------------------------
# Get roles associated with a user by DN (not sAMAccountName)
# Expects you to pass it in a pre-bound connection to the LDAP server 
#---------------------------------------------------------------------------------
def getUserRoles(userDN,connection):
    roles = [ ]

    # Complicated crap to make a search filter.  The whole idea is to be able to
    # search for groups that are defined as a role-mapped group and *also* have
    # the user as a member.

    filter=''.join( [ '(&', 
    '(|', ''.join([ '(CN=' + ldap3.utils.conv.escape_filter_chars(j) + ')' for j in groups_to_roles.keys() ]) , ')',
    '(member=', ldap3.utils.conv.escape_filter_chars(userDN), ')',
    ')' ])
    results=connection.search(search_base = group_base_dn,
        search_filter = filter,
        search_scope = ldap3.SUBTREE,
        attributes = [ 'cn' ])
    if len(connection.entries) > 0:
        for j in connection.entries:
            if str(j['cn']) in groups_to_roles:
                roles.extend([ groups_to_roles[str(j['cn'])] ])
            else:
                # This should never ever happen because our search filter
                # should have already limited us to *only* groups listed in
                # the groups_to_roles dict.   A group cannot both be in,
                # and not-in that list simultaneously
                logger.error("unable to find " + repr(j['cn']) + " in groups_to_roles")
            
    #return list( more_itertools.unique_everseen(roles) )
    return list( more_itertools.unique_everseen(flatten(roles)) )

#---------------------------------------------------------------------------------
# Helper to format a scripted auth line in the way splunk expects it
#---------------------------------------------------------------------------------
def makeUserInfo(u,realname,roles):
    return ' --userInfo=;%s;%s;%s' % (u,realname,':'.join(roles))


#--------------------------------------------------------------------------------
# Get one user's info from LDAP using DN
#    Expects two otherwise unused, already-bound LDAP connections
#--------------------------------------------------------------------------------
def ldapUserInfo(dn,conn2,conn3):

    def getItem(a,field,default=""):
        if a.get(field,None) is not None:
            return a.get(field)[0]
        else:
            return default

    attributes = [ 'sAMAccountName', 'displayName', 'mail' ]
    #attributes.extend ( ldap_yubikey_attributes )

    results=conn2.search(search_base = dn,
        search_filter = '(objectclass=*)',
        search_scope = ldap3.BASE,
        attributes = attributes)

    if len(conn2.response) == 1:
        a=conn2.response[0]['attributes']

        sAMAccountName = getItem(a,'sAMAccountName')
        user_dict = { }
        user_dict['displayName']=getItem(a,'mail',default=sAMAccountName)
        user_dict['mail']=getItem(a,'mail',default=sAMAccountName+"@place.com")
        user_dict['dn']=dn
        #templist = testing_yubikeys 
        #for q in ldap_yubikey_attributes:
        #    templist.extend(a.get(q,[ ]))
        #user_dict['yubikeys'] =  list( more_itertools.unique_everseen(templist) )
        

        # Reusing conn2 here, which might be risky but
        # reusing it LAST so that we don't get into trouble 
        user_dict['roles']=getUserRoles(dn,conn3)

        return(sAMAccountName,user_dict)
    
    # ELSE
    return None
        

#--------------------------------------------------------------------------------
# Dump all splunk-eligible users from LDAP into a dictionary
#   Uses an ldap filter to list all of the people who are members of any group
#   that is mappped to a role.  From there, iterate across the people and figure
#   out which groups they are in and build roles out of that.  We did not use
#   the memberOf attribute specifically because of not being guaranteed that
#   a non-AD LDAP server would have it.
#--------------------------------------------------------------------------------
def ldapUsers():

    conn=ldapConnectionFactory()
    conn2=ldapConnectionFactory()
    conn3=ldapConnectionFactory()

    group_search_filter='(|' + ''.join([ '(CN=' + j + ')' for j in groups_to_roles.keys() ]) + ')'

    results = conn.extend.standard.paged_search(search_base = group_base_dn,
                search_filter = group_search_filter,
                search_scope = ldap3.SUBTREE,
                attributes = ['member'],
                paged_size = 5,
                generator = True)

    users = { }

    for r in results:
        if 'member' in r['attributes']:
            for x in r['attributes']['member']:
                (name,user_dict) = ldapUserInfo(x,conn2,conn3)
                if name not in users:
                    users[name]=user_dict

    return users
                

#------------------------------------------------------------------------------
# Expects you to supply an active connection 
#------------------------------------------------------------------------------
def getDNforsAMAccountName(name,conn):

    # All we're doing here is getting the dn associated with a sAMAccountName
    results=conn.search(search_base = user_base_dn,
        search_filter = '(sAMAccountName=%s)' % name,
        search_scope = ldap3.SUBTREE)
        #attributes = [ 'sAMAccountName', 'displayName', 'mail' ])

    if len(conn.response) == 1:
        dn=conn.response[0]['dn']
        return dn
    
    # else
    return None

#------------------------------------------------------------------------------
# external API entry
# Dump details of one user
#------------------------------------------------------------------------------
def getUserInfo( args ):
    conn=ldapConnectionFactory()
    conn2=ldapConnectionFactory()

    dn = getDNforsAMAccountName(args.get(USERNAME,None),conn)
    if dn is not None:
        (name,user_dict) = ldapUserInfo(dn,conn,conn2)
        if len(user_dict['roles']) > 0:
            print (SUCCESS + makeUserInfo(name,user_dict['displayName'],user_dict['roles']))
        else:
            logger.error("User has no roles?")
            print (FAILED)
    else:
        logger.error("Weird state.  Splunk asked us to pull user information on a user we could not find...")
        print (FAILED)


#------------------------------------------------------------------------------
# external API entry
# Dump all the users that exist as a member of a group that is mapped to a role
#------------------------------------------------------------------------------
def getUsers( args ):
    out = SUCCESS
    users = ldapUsers()
    for user in users:
        out = out + makeUserInfo(user,users[user]['displayName'],users[user]['roles'])
    print (out)


#--------------------------------------------------------------------------------
# external API entry
# Log some one in :)
#--------------------------------------------------------------------------------
def userLogin(args):
    conn=ldapConnectionFactory()
    conn2=ldapConnectionFactory()
    user=args[USERNAME]

    dn = getDNforsAMAccountName(user,conn)
    if dn is None:
        logger.error("Could not map username to DN")
        print ( FAILED )
        return

    # Yubikey OTP is 44-characters so if there's not at least 45 chars then
    # we assume there's only a single factor and fail them out of spite 
    # also fail out of spite if the user does not have a yubikey in their password entry
    if (len(args['password']) < 45):
       print(FAILED)
       logger.error("Password too short to have yubi token")
       return


    # Otherwise split the first and second factors apart
    password=args['password'][0:-44]
    yubiotp=args['password'][-44:]
    yubikeyid=yubiotp[0:12]

    # Go get the additional information about the user from AD
    (account_name,user_dict) = ldapUserInfo(dn,conn,conn2)

    # Try to bind as the user to LDAP
    # The ability to skip the first factor for someone is horribly insecure but
    # for testing purposes we'll allow it.
    if user not in skip_first_factor_users:
        server = ldap3.ServerPool(ldap_servers, ldap3.POOLING_STRATEGY_ROUND_ROBIN, active=True, exhaust=True)
        usertestconn = ldap3.Connection(server, user_dict['dn'], password, check_names=True)
        if not usertestconn.bind():
            print(FAILED)
            logger.error("AD Bind as %s [%s] failed" % (account_name,user_dict['dn']))
            return

    if (len(user_dict['roles']) == 0):
        print(FAILED)
        logger.error("User has no roles")
        return
  
    try:
       srv = Client(server="auth.radius.com", secret="",
           dict = Dictionary("dictionary"))
       req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest, 
                                  User_Name=user)
       req["User-Password"] = req.PwCrypt(yubiotp)
       reply = srv.SendPacket(req)
       if reply.code == pyrad.packet.AccessAccept:
           logger.info("Logged in successfully as %s using yubikey %s" % (user, yubikeyid))
           print(SUCCESS)
           return
       else:
           logger.info("FAILED TO LOG IN as %s using yubikey %s" % (user, yubikeyid))
           print(FAILED)
           return
    except Exception as e:
       logging.error("Exception in Radius verify: %s \nSee stack trace:", e)
       raise

    # If we fall all the way out
    logit("Fell out the bottom")
    print(FAILED)


#--------------------------------------------------------------------------
# external API entry
# Give someone a search filter - this is mostly a dummy method
#--------------------------------------------------------------------------------
def getSearchFilter( args ):
    
    if getDNforsAMAccountName(args[USERNAME],ldapConnectionFactory()) != None:
        print (SUCCESS)
    else:
        print (FAILED)


if __name__ == "__main__":
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


import random
from os import urandom
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_512, HMAC, SHA256, SHA3_256
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from kyber_py.kyber import Kyber1024

API_URL = 'http://harpoon1.sabanciuniv.edu:9997/'

stuID = 32353
stuIDB = 18007

def IKRegReq(R,s,x,y):
    mes = {'ID':stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    if((response.ok) == False): print(response.json())

def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    print(response.json())

def SPKReg(R,s,x,y):
    mes = {'ID':stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)	
    print(response.json())

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

# New (register) function for PQOTKs 
def PQOTKReg(keyID, pqotk_hex, R, s):
    mes = {'ID':stuID, 'KEYID': keyID, 'PQOTKI': pqotk_hex, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print(f"Registering PQ OTK {keyID}...")
    response = requests.put('{}/{}'.format(API_URL, "PQOTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(R,s):
    mes = {'ID':stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetOTK(R,s):
    mes = {'ID':stuID,'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    print(response.json())

def PseudoSendMsg(R,s):
    mes = {'ID':stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

def ReqMsg(R,s):
    mes = {'ID':stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return (
            res["IDB"],
            res["OTKID"],
            res["MSGID"],
            res["MSG"],
            res["IK.X"],
            res["IK.Y"],
            res["EK.X"],
            res["EK.Y"],
            res.get("PQKEYID"),
            res.get("PQCT", "")
        )

def ReqDelMsg(R,s):
    mes = {'ID':stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

def SendMsg(idA, idB, otkid, msgid, msg, ikx, iky, ekx, eky, pqkeyid=None, pqct=""):
    mes = {
        "IDA": idA, 
        "IDB": idB, 
        "OTKID": int(otkid) if otkid is not None else None, 
        "MSGID": msgid, 
        "MSG": msg, 
        "IK.X": ikx, 
        "IK.Y": iky, 
        "EK.X": ekx, 
        "EK.Y": eky,
        "PQKEYID": pqkeyid,
        "PQCT": pqct
    }
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json = mes)
    print(response.json())
    
def ReqKeyBundle(stuID, stuIDB, R, s):
    OTK_request_msg = {'IDA': stuID, 'IDB':stuIDB, 'R.X':R.x, 'R.Y':R.y, 'S': s}
    print("Requesting party B's key bundle (EC + PQ keys)...")
    response = requests.get('{}/{}'.format(API_URL, "ReqKeyBundle"), json = OTK_request_msg)
    print(response.json()) 
    if((response.ok) == True):
        res = response.json()
        return (res.get('KEYID'), res['IK.X'], res['IK.Y'], res['SPK.X'], res['SPK.Y'], 
                res['SPK.R.X'], res['SPK.R.Y'], res['SPK.S'], res.get('OTK.X'), res.get('OTK.Y'),
                res.get('PQKEYID'), res.get('PQPK'), res.get('PQPK.R.X'), res.get('PQPK.R.Y'), 
                res.get('PQPK.S'))
    else:
        return (None, 0, 0, 0, 0, 0, 0, 0, 0, 0, None, None, 0, 0, 0)

def Status(stuID, R, s):
    mes = {'ID':stuID, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json = mes)	
    if (response.ok == True):
        res = response.json()
        return res.get('numMSG'), res.get('numOTK'), res.get('numPQOTK', 0), res.get('StatusMSG')	


### New functions for conference keying

# Exchange partial keys with users 2 and 4
def ExchangePartialKeys(stuID, z1x, z1y, R, s):
    request_msg = {'ID': stuID, 'z1.x': z1x, 'z1.y': z1y, 'R.X': R.x, 'R.Y': R.y,'S': s}
    print("Sending your PK (z) and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangePartialKeys"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['z2.x'], res['z2.y'], res['z4.x'], res['z4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0


# Exchange partial keys with user 3
def ExchangeXs(stuID, x1x, x1y, R, s):
    request_msg = {'ID': stuID, 'x1.x': x1x, 'x1.y': x1y, 'R.X': R.x, 'R.Y': R.y, 'S': s}
    print("Sending your x and receiving others ...")
    response = requests.get('{}/{}'.format(API_URL, "ExchangeXs"), json=request_msg)
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['x2.x'], res['x2.y'], res['x3.x'], res['x3.y'], res['x4.x'], res['x4.y']
    else:
        print(response.json())
        return 0, 0, 0, 0, 0, 0

# Check if your conference key is correct
def BonusChecker(stuID, Kx, Ky):
    mes = {'ID': stuID, 'K.x': Kx, 'K.y': Ky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "BonusChecker"), json=mes)
    print(response.json())

#REST IS MY IMPLEMENTATION#

def KeyGen(Curve):
    #Generate private key
    sA = random.randint(1, Curve.order - 1)
    #Generate public key
    Q = sA * Curve.generator
    return sA, Q

def SignGen(Curve, message, sA, QA):
    n = Curve.order
    P = Curve.generator
    #following algorithm described in Section 2.4 of the Project document
    #1st step: compute h1
    sA_bytes = sA.to_bytes((sA.bit_length() + 7) // 8, byteorder='big')
    h1 = SHA3_512.new(sA_bytes).digest()

    #2nd step: compute r
    r_input = h1[32:] + message
    r_hash = SHA3_512.new(r_input).digest()
    r = int.from_bytes(r_hash, byteorder='big') % n

    #3rd step: compute R
    R = r * P
    
    #4th step: compute h2
    Rx_bytes = R.x.to_bytes(32, byteorder='big')
    Ry_bytes = R.y.to_bytes(32, byteorder='big')
    QAx_bytes = QA.x.to_bytes(32, byteorder='big')
    QAy_bytes = QA.y.to_bytes(32, byteorder='big')
    
    h2_input = Rx_bytes + Ry_bytes + QAx_bytes + QAy_bytes + message
    h2_hash = SHA3_512.new(h2_input).digest()
    h2 = int.from_bytes(h2_hash, byteorder='big') % n

    #5th step: compute s
    s = (r + sA * h2) % n

    #return the signature tuple
    return R, s

def SignVer(message, R, s, QA, Curve):
    n = Curve.order
    P = Curve.generator

    #following algorithm described in Section 2.4 of the Project document
    #1st step: compute h2
    Rx_bytes = R.x.to_bytes(32, byteorder='big')
    Ry_bytes = R.y.to_bytes(32, byteorder='big')
    QAx_bytes = QA.x.to_bytes(32, byteorder='big')
    QAy_bytes = QA.y.to_bytes(32, byteorder='big')
    
    h_input = Rx_bytes + Ry_bytes + QAx_bytes + QAy_bytes + message
    h_hash = SHA3_512.new(h_input).digest()
    h = int.from_bytes(h_hash, byteorder='big') % n
    
    #2nd step: compute v1
    v1 = s * P
    
    #3rd step: compute v2
    v2 = R + (h * QA)
    
    if v1 == v2:
        return True
    else:
        return False
    
stuID_bytes = stuID.to_bytes((stuID.bit_length() + 7) // 8, byteorder='big')

#part that I form the server's IK
projCurve = Curve.get_curve('Ed25519')

server_IK_x_hex = 0x2eef2e2656fb3d8c3c4932c679fbca121c2ea5fe26deecd800bc9311ef06f06
server_IK_y_hex = 0x17a8a7f452068d1157a974abc69cd5ae83d528936b4c1d8dab6095d28eeedcc0
server_IK_x_dec = int(server_IK_x_hex)
server_IK_y_dec = int(server_IK_y_hex)

IKey_Ser = Point(server_IK_x_dec, server_IK_y_dec, projCurve) 

#Generation and Registration of my IK
IKA_Pri, IKA_Pub = KeyGen(projCurve)
print("Identity Key Generated.")

R_IK, s_IK = SignGen(projCurve, stuID_bytes, IKA_Pri, IKA_Pub)

print("Signed my ID.")

print("Sent IK registration request.")
IKRegReq(R_IK, s_IK, IKA_Pub.x, IKA_Pub.y)

#Authentication of the code received by email
code = int(input("Enter the code received by email: "))  #actual code received by email
print("Sent IK registration verification.")
IKRegVerify(code)

#Generation and Registration of my SPK
SPKA_Pri, SPKA_Pub = KeyGen(projCurve)
print("Generated my SPK.")

spk_x_bytes = SPKA_Pub.x.to_bytes(32, byteorder='big')
spk_y_bytes = SPKA_Pub.y.to_bytes(32, byteorder='big')
spk_message = spk_x_bytes + spk_y_bytes

R_SPK, s_SPK = SignGen(projCurve, spk_message, IKA_Pri, IKA_Pub)
print("Signed my SPK.")

print("Sent SPK registration.")
SPKReg(R_SPK, s_SPK, SPKA_Pub.x, SPKA_Pub.y)

#Generation and Registration of my OTKs

T = SPKA_Pri * IKey_Ser

T_x_bytes = T.x.to_bytes(32, byteorder='big')
T_y_bytes = T.y.to_bytes(32, byteorder='big')
U = b'TheHMACKeyToSuccess' + T_y_bytes + T_x_bytes

K_HMAC = SHA3_256.new(U).digest()
print("HMAC Key Generated.")

OTK_Pri_Dict = {}  #to store private keys of OTKs for later use

for i in range(10):
    #generate OTK Key Pair
    OTK_Pri, OTK_Pub = KeyGen(projCurve)
    OTK_Pri_Dict[i] = OTK_Pri

    otk_x_bytes = OTK_Pub.x.to_bytes(32, byteorder='big')
    otk_y_bytes = OTK_Pub.y.to_bytes(32, byteorder='big')
    otk_message = otk_x_bytes + otk_y_bytes
    
    hmac_obj = HMAC.new(K_HMAC, msg=otk_message, digestmod=SHA256)
    hmac_val = hmac_obj.hexdigest() #server expects hex string
    
    #register each OTK
    OTKReg(i, int(OTK_Pub.x), int(OTK_Pub.y), hmac_val)

print("OTKs Registered.")

# PQOTK (Kyber) Registration
my_pqotks = {}  #storing the private keys for decryption

for i in range(10):
    # Generate Kyber Key Pair
    pk, sk = Kyber1024.keygen()
    # Save private key for later decryption
    my_pqotks[i] = sk
    
    # Sign the Public Key (pk is bytes)
    R_pq, s_pq = SignGen(projCurve, pk, IKA_Pri, IKA_Pub)
    
    # Register (Convert bytes to hex string for the helper function)
    PQOTKReg(i, pk.hex(), R_pq, s_pq)

print("PQOTKs Registered Successfully.")

# CONFERENCE KEYING
print("\n=== CONFERENCE KEYING ===")

#generate the random value r1 and compute z1
r1 = random.randint(1, projCurve.order - 1)
z1 = r1 * projCurve.generator

#sign the incremented form of z1
z1_bytes = z1.x.to_bytes(32, 'big') + z1.y.to_bytes(32, 'big')
R_conf, s_conf = SignGen(projCurve, z1_bytes, IKA_Pri, IKA_Pub)

# Exchange z values- Send z1, receive z2 and z4
z2x, z2y, z4x, z4y = ExchangePartialKeys(stuID, z1.x, z1.y, R_conf, s_conf)

if z2x != 0:
    z2 = Point(z2x, z2y, projCurve)
    z4 = Point(z4x, z4y, projCurve)
   
    x1_point = r1 * (z2 - z4)
    # Sign and exchange x values
    x1_bytes = x1_point.x.to_bytes(32, 'big') + x1_point.y.to_bytes(32, 'big')
    R_x1, s_x1 = SignGen(projCurve, x1_bytes, IKA_Pri, IKA_Pub)
    print("Signed x1.")

    x2x, x2y, x3x, x3y, x4x, x4y = ExchangeXs(stuID, x1_point.x, x1_point.y, R_x1, s_x1)

    if x2x != 0:
        x2 = Point(x2x, x2y, projCurve)
        x3 = Point(x3x, x3y, projCurve)
        x4 = Point(x4x, x4y, projCurve)
        
        K_conf = (4 * r1) * z4 + 3 * x1_point + 2 * x2 + x3
      
        print("Verifying conference key with server...")
        BonusChecker(stuID, K_conf.x, K_conf.y)
        print("Conference key establishment complete!")

#PQXDH MESSAGING (RECEIVING)
print("\n=== PQXDH MESSAGING - RECEIVING ===")

# Generate authentication signature
R_auth, s_auth = SignGen(projCurve, stuID_bytes, IKA_Pri, IKA_Pub)

# make client to send messages
print("Requesting 5 messages from pseudo-client...")
PseudoSendMsg(R_auth, s_auth)

valid_msgs = {}
all_msg_ids = []
KS = None

# Download 5 Messages
for i in range(5):
    data = ReqMsg(R_auth, s_auth)
    if not data: 
        continue
    
    # Unpack Response
    IDB, OTKID, MSGID, MSG_INT, IKx, IKy, EKx, EKy, PQKEYID, PQCT_HEX = data
    all_msg_ids.append(MSGID)
    
    # Convert Message to Bytes
    msg_len = (MSG_INT.bit_length() + 7) // 8
    MSG_BYTES = MSG_INT.to_bytes(msg_len, 'big')
    nonce, cipher, mac = MSG_BYTES[:8], MSG_BYTES[8:-32], MSG_BYTES[-32:]
    
    IK_Pub_Sender = Point(IKx, IKy, projCurve)
    EK_Pub_Sender = Point(EKx, EKy, projCurve)

    # Calculate Session Key starting from 1st message
    if KS is None:
        print(f"\nInitializing PQXDH Session with OTK {OTKID} and PQOTK {PQKEYID}...")
        
        #Classical X3DH Secrets of receiver
        T1 = SPKA_Pri * IK_Pub_Sender
        T2 = IKA_Pri * EK_Pub_Sender
        T3 = SPKA_Pri * EK_Pub_Sender
        T4 = OTK_Pri_Dict[OTKID] * EK_Pub_Sender
        
        #Post-Quantum Decapsulation
        my_pq_sk = my_pqotks[PQKEYID]
        pq_ct_bytes = bytes.fromhex(PQCT_HEX)
        
        K_PQ = Kyber1024.decaps(my_pq_sk, pq_ct_bytes)

        #Combine All Secrets to form Session Key
        U = b''
        for t in [T1, T2, T3, T4]:
            U += t.x.to_bytes(32, 'big') + t.y.to_bytes(32, 'big')
        U += K_PQ + b'WhatsUpDoc'
        KS = SHA3_256.new(U).digest()
        print("Session Key KS generated successfully.")
        
    # KDF Chain for each message
    K_ENC = SHA3_256.new(KS + b'JustKeepSwimming').digest()
    K_HMAC = SHA3_256.new(KS + K_ENC + b'HakunaMatata').digest()
    K_NEXT = SHA3_256.new(K_ENC + K_HMAC + b'OhanaMeansFamily').digest()
    KS = K_NEXT
    
    # Verify HMAC
    hmac_calc = HMAC.new(K_HMAC, msg=cipher, digestmod=SHA256).digest()

    if hmac_calc == mac:
        try:
            dec_bytes = AES.new(K_ENC, AES.MODE_CTR, nonce=nonce).decrypt(cipher)
            dec_txt = dec_bytes.decode('utf-8')
            print(f"Message {MSGID}: {dec_txt}")
            valid_msgs[MSGID] = dec_txt
            Checker(stuID, IDB, MSGID, dec_txt)
        except Exception as e:
            print(f"Message {MSGID}: Decryption Failed - {e}")
            Checker(stuID, IDB, MSGID, "INVALIDHMAC")
    else:
        print(f"Message {MSGID}: HMAC INVALID")
        Checker(stuID, IDB, MSGID, "INVALIDHMAC")

#DISPLAY FINAL MESSAGE BLOCK
deleted_ids = ReqDelMsg(R_auth, s_auth)

print("\nFinal Message Block Display:")
for msg_id in sorted(all_msg_ids):
    if msg_id in deleted_ids:
        print(f"Message {msg_id}: This message was deleted")
    elif msg_id in valid_msgs:
        print(f"Message {msg_id}: {valid_msgs[msg_id]}")

#SEND MESSAGES BACK
print("\n=== SENDING MESSAGES BACK ===")

idb_bytes = stuIDB.to_bytes((stuIDB.bit_length() + 7) // 8, 'big')
R_bundle, s_bundle = SignGen(projCurve, idb_bytes, IKA_Pri, IKA_Pub)
# Get Key Bundle from pseudo-client 
bundle = ReqKeyBundle(stuID, stuIDB, R_bundle, s_bundle)

if bundle[0] is not None:
    (OTKID, IK_X, IK_Y, SPK_X, SPK_Y, SPK_RX, SPK_RY, SPK_S, OTK_X, OTK_Y, 
        PQKEYID_B, PQPK_B_HEX, PQPK_RX, PQPK_RY, PQPK_S) = bundle
        
    IK_B = Point(IK_X, IK_Y, projCurve)
    SPK_B = Point(SPK_X, SPK_Y, projCurve)
    OTK_B = Point(OTK_X, OTK_Y, projCurve)
    SPK_R = Point(SPK_RX, SPK_RY, projCurve)
    PQPK_R = Point(PQPK_RX, PQPK_RY, projCurve)
    
    # Verify SPK signature
    spk_x_bytes = SPK_B.x.to_bytes((SPK_B.x.bit_length() + 7) // 8, 'big')
    spk_y_bytes = SPK_B.y.to_bytes((SPK_B.y.bit_length() + 7) // 8, 'big')
    spk_msg = spk_x_bytes + spk_y_bytes
    spk_verified = SignVer(spk_msg, SPK_R, SPK_S, IK_B, projCurve)
    
    # Verify PQPK signature
    pqpk_msg = bytes.fromhex(PQPK_B_HEX)
    pqpk_verified = SignVer(pqpk_msg, PQPK_R, PQPK_S, IK_B, projCurve)
    
    if spk_verified and pqpk_verified:
        print("Target SPK and PQPK verified successfully.")
        
        # Generate Ephemeral Key
        EK_Pri, EK_Pub = KeyGen(projCurve)
        
        #Classical X3DH Secrets of sender this time
        T1 = IKA_Pri * SPK_B
        T2 = EK_Pri * IK_B
        T3 = EK_Pri * SPK_B
        T4 = EK_Pri * OTK_B

        #Post-Quantum Encapsulation
        pq_pk_bytes = bytes.fromhex(PQPK_B_HEX)
        K_PQ, C_PQ = Kyber1024.encaps(pq_pk_bytes)
        
        #Compute Session Key
        U = b''
        for t in [T1, T2, T3, T4]:
            U += t.x.to_bytes(32, 'big') + t.y.to_bytes(32, 'big')
        U += K_PQ + b'WhatsUpDoc'
        KS_Send = SHA3_256.new(U).digest()
        print("Sender Session Key KS generated successfully.")
        
        #Encrypt and Send Messages (only undeleted valid (decrypted and having hmac verified) messages)
        messages_to_send = [msg_id for msg_id in sorted(valid_msgs.keys()) if msg_id not in deleted_ids]
        
        for msg_id in sorted(valid_msgs.keys()):
            # Run KDF for this message
            K_ENC = SHA3_256.new(KS_Send + b'JustKeepSwimming').digest()
            K_HMAC = SHA3_256.new(KS_Send + K_ENC + b'HakunaMatata').digest()
            K_NEXT = SHA3_256.new(K_ENC + K_HMAC + b'OhanaMeansFamily').digest()
            KS_Send = K_NEXT
            
            # Only send if not deleted
            if msg_id not in deleted_ids:
                print(f"\nSending Message {msg_id}...")
                nonce = urandom(8)
                cipher = AES.new(K_ENC, AES.MODE_CTR, nonce=nonce).encrypt(valid_msgs[msg_id].encode())
                hmac_val = HMAC.new(K_HMAC, msg=cipher, digestmod=SHA256).digest()
                final_msg_int = int.from_bytes(nonce + cipher + hmac_val, 'big')
                
                # Convert Kyber Ciphertext to Hex String
                C_PQ_HEX = C_PQ.hex()
                
                SendMsg(stuID, stuIDB, OTKID, msg_id, final_msg_int, 
                       IKA_Pub.x, IKA_Pub.y, EK_Pub.x, EK_Pub.y, 
                       pqkeyid=PQKEYID_B, pqct=C_PQ_HEX)

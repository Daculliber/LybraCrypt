__version__ = "3.2"
import hashlib, secrets, os
import base64,json
class LybraCrypt:
    def __init__(self,key:bytes or None =None,lybra_path:str or None=None):
        #turning the key in a hash and getting the int of every byte of the hash in one list
        if key:
            self.key=hashlib.sha256(key).digest()
        if lybra_path==None:
            pass
        elif os.path.exists(lybra_path) and lybra_path:
            with open(lybra_path,"r") as file:
                self.Lybra=json.load(file)
        else:
            raise Exception("Lybra file not found")
    def retrieve_parts(self,data: bytes) -> bytes:
        nonce_salt = data[:26]    # Take the first 10 bytes
        nonce=nonce_salt[:16]
        salt=nonce_salt[16:]
        data = data[26:]
        return nonce, salt, data
    #lybra
    def bin_encode(self,binary_data):    
        return base64.b64encode(binary_data).decode('utf-8')
    def bin_decode(self,base64_data):
        return base64.b64decode(base64_data)
    def generate_lybra(self, path: str,codes_per_byte:int =1000):
        if codes_per_byte > 1000000:
            print(f"Can't generate a Lybra with {codes_per_byte} per byte.")
            print("For performance reasons the limit is 1,000,000. \nFor efficiency reasons we will generate a Lybra with 1.000 codes per byte. \nThis is already safe enough for most applications.")
            codes_per_byte=1000
        print(f"Generating Lybra with {codes_per_byte} possible codes for every byte.")
        self.Lybra={}
        lybra={}
        all_codes_check= set()
        code=""
        for i in range(256):
            print(f"{i} /256")
            codes=[]
            for c in range(codes_per_byte):
                code=self.bin_encode(secrets.token_bytes(5))
                while code in all_codes_check:
                    code=self.bin_encode(secrets.token_bytes(5))
                codes.append(code)
            lybra[str(i)]=codes
        self.Lybra["lybra"]=lybra
        reverse={}
        for byte in lybra:
            for code in lybra[byte]:
                reverse[code]=byte
        self.Lybra["reverse"]=reverse
        print(f"Saving to file {path}")
        with open(path,"w") as file:
            json.dump(self.Lybra,file)
        print("done")
    def get_code(self, bite:int) -> bytes:
        lyb=self.Lybra["lybra"]
        return bytes(self.bin_decode(secrets.choice(lyb[str(bite)])))
    def get_byte(self,code: bytes) -> int:
        rev=self.Lybra["reverse"]
        return int(rev[self.bin_encode(code)])
        
    #byte encryption 

    def xor_stream_cipher(self,data: bytes, key: bytes, nonce: bytes) -> bytes:
        """
        Encrypts or decrypts data using a secure, rolling counter-based SHA-512 keystream.
        Because XOR is symmetric, the exact same function encrypts AND decrypts.
        """
        output = bytearray()
        block_size = 64  # SHA-512 outputs 64-byte blocks
        counter = 0
        
        # Process the data in 64-byte chunks
        for i in range(0, len(data), block_size):
            chunk = data[i:i+block_size]
            
            # 1. Roll the key forward safely by hashing Key + Nonce + Counter
            # This creates a completely unpredictable 64-byte keystream block
            keystream_block = hashlib.sha512(key + nonce + str(counter).encode()).digest()
            
            # 2. XOR the data chunk with the keystream block byte-by-byte
            for j in range(len(chunk)):
                output.append(chunk[j] ^ keystream_block[j])
                
            counter += 1
            
        return bytes(output)  

    #encryption
    def encrypt(self,data:bytes) -> bytes:
        nonce=secrets.token_bytes(16)
        salt=secrets.token_bytes(10)
        key=hashlib.sha256(self.key+salt).digest()
        data_list=[int(i) for i in data] #turning the binary data into a list of ints
        enc_bytes=[] #encoding with lybra
        for int_value in data_list:
            enc_bytes.append(self.get_code(int_value))
        data=b"".join(enc_bytes)
        h_data=hashlib.sha256(data+key).digest()+data #hashing to prevent tampering before final xor to prevent making a new hash
        data=self.xor_stream_cipher(data=h_data ,key=key,nonce=nonce)

        return nonce+salt +data
    
    

    def decrypt(self,data:bytes) -> bytes:
        try:
            nonce, salt,data=self.retrieve_parts(data)
            key=hashlib.sha256(self.key+salt).digest()
            code_length=5
            
            h_data=self.xor_stream_cipher(data,key,nonce)#removing xor
            h=h_data[:32]
            data=h_data[32:]
            h_check=hashlib.sha256(data+key).digest() #generating the same hash to test
            if h != h_check:
                raise Exception("Invalid certificate or incorrect key")
            #decoding with lybra
            codes = [data[i:i + code_length] for i in range(0, len(data), code_length)]
            dec = bytes([self.get_byte(code) for code in codes])
            return dec
        except KeyError:
            raise Exception("Invalid code. The data is corrupted or the password or lybra is incorrect.")    
#demonstration
#l=LybraCrypt(b"yruihncehn",lybra_path="l.lyb")
#l.generate_lybra("l.lyb")
#a=l.encrypt(b"hello world")

#print(l.decrypt(a))

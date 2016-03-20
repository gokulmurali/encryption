import sys


class base_des(object):

    ## CLASS FOR BASIC DES OPERATIONS ## 
    def __init__(self):
        self.decrypt = False
        self.tmp = []

    ## PADDING TO BE ADDED WHEN MESSAGE IS NOT A MULTIPLE OF 8 BYTES
    ## OR PASSWORD PROVIDED FOR KEY IS NOT 56 BITS
    text_pad = "0b10000001"      
    key_pad = "0b11110000"

    ######  PERMUTATION S & P BOXES #######    

    ## INITIAL PERMUTATION ##
    IP = []
    IP = [58, 50, 42, 34, 26, 18, 10, 2,
          60, 52, 44, 36, 28, 20, 12, 4,
          62, 54, 46, 38, 30, 22, 14, 6,
          64, 56, 48, 40, 32, 24, 16, 8,
          57, 49, 41, 33, 25, 17, 9,  1,
          59, 51, 43, 35, 27, 19, 11, 3,
          61, 53, 45, 37, 29, 21, 13, 5,
          63, 55, 47, 39, 31, 23, 15, 7]  


    ## FINAL PERMUATION INVERSE OF INITIAL PERMUTATION ##
    FP = []
    FP = [40, 8, 48, 16, 56, 24, 64, 32,
          39, 7, 47, 15, 55, 23, 63, 31,
          38, 6, 46, 14, 54, 22, 62, 30,
          37, 5, 45, 13, 53, 21, 61, 29,
          36, 4, 44, 12, 52, 20, 60, 28,
          35, 3, 43, 11, 51, 19, 59, 27,
          34, 2, 42, 10, 50, 18, 58, 26,
          33, 1, 41,  9, 49, 17, 57, 25]


    ## EXPANSION PERMUATION ##
    E = []
    E = [32,  1,  2,  3,  4,  5,
          4,  5,  6,  7,  8,  9,
          8,  9, 10, 11, 12, 13,
         12, 13, 14, 15, 16, 17,
         16, 17, 18, 19, 20, 21,
         20, 21, 22, 23, 24, 25,
         24, 25, 26, 27, 28, 29,
         28, 29, 30, 31, 32,  1]

    ## S-BOXES ## 
    S = [[0 for x in xrange(64)] for x in xrange(8)]
    S = [[14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,   7,
           0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,   8,
           4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,   0,
          15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6,  13], 
 
         [15,  1,  8, 14,  6, 11,  3,  4,  9, 7,  2, 13, 12, 0,  5, 10,
           3, 13,  4,  7, 15,  2,  8, 14, 12, 0,  1, 10,  6, 9, 11,  5,
           0, 14,  7, 11, 10,  4, 13,  1,  5, 8, 12,  6,  9, 3,  2, 15,
          13,  8, 10,  1,  3, 15,  4,  2, 11, 6,  7, 12,  0, 5, 14,  9], 
       
         [10,  0,  9, 14, 6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
          13,  7,  0,  9, 3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
          13,  6,  4,  9, 8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
           1, 10, 13,  0, 6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12], 
       
         [ 7, 13, 14, 3,  0,  6,  9,  10, 1,  2,  8,  5,  11, 12, 4,  15,
          13,  8, 11, 5,  6, 15,  0,  3,  4,  7,  2,  12, 1,  10, 14, 9,
          10,  6,  9, 0, 12, 11,  7,  13, 15, 1,  3,  14, 5,  2,  8,  4,
           3, 15,  0, 6, 10,  1, 13, 8,  9,  4,  5,  11, 12, 7,  2,  14],
 
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13, 0, 14,  9,
         14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3, 9,  8,  6,
          4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6, 3,  0, 14,
         11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10, 4,  5,  3],
 
        [12,  1, 10, 15, 9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
         10, 15,  4,  2, 7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
          9, 14, 15,  5, 2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
          4,  3,  2, 12, 9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
 
        [ 4, 11,  2, 14, 15, 0,  8, 13,  3, 12, 9,  7,  5, 10, 6,  1,
         13,  0, 11,  7,  4, 9,  1, 10, 14,  3, 5, 12,  2, 15, 8,  6,
          1,  4, 11, 13, 12, 3,  7, 14, 10, 15, 6,  8,  0,  5, 9,  2,
          6, 11, 13,  8,  1, 4, 10,  7,  9,  5, 0, 15, 14,  2, 3, 12],
 
        [13,  2,  8, 4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
          1, 15, 13, 8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
          7, 11,  4, 1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
          2,  1, 14, 7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]

   
    P = []
    P = [16,  7, 20, 21,
         29, 12, 28, 17,
          1, 15, 23, 26,
          5, 18, 31, 10,
          2,  8, 24, 14,
         32, 27,  3,  9,
         19, 13, 30,  6,
         22, 11,  4, 25]

    PC1 = []
    PC1 = [57, 49, 41, 33, 25, 17,  9,
            1, 58, 50, 42, 34, 26, 18,
           10,  2, 59, 51, 43, 35, 27,
           19, 11,  3, 60, 52, 44, 36,
           63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
           14,  6, 61, 53, 45, 37, 29,
           21, 13,  5, 28, 20, 12,  4]


    PC2 = []
    PC2 = [14, 17, 11, 24,  1,  5,
            3, 28, 15,  6, 21, 10,
           23, 19, 12,  4, 26,  8,
           16,  7, 27, 20, 13,  2,
           41, 52, 31, 37, 47, 55,
           30, 40, 51, 45, 33, 48,
           44, 49, 39, 56, 34, 53,
           46, 42, 50, 36, 29, 32]

    ## SHIFTS ## 
    rotations = []
    rotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


        
    ## FUNCIONS IN DES ##
    def IP_f(self, src): return self.permute(self.IP, 64, src)                 
    def FP_f(self, src): return self.permute(self.FP, 64, src)                 
    def E_f(self, src): return self.permute(self.E, 32, src&0xFFFFFFFF)      
    def P_f(self, src): return self.permute(self.P, 32, src&0xFFFFFFFF) 
    def PC1_f(self, src): return self.permute(self.PC1, 64, src)                
    def PC2_f(self, src): return self.permute(self.PC2, 56, src)                


    ## IMPLEMENTATION OF VARIOUS PERMUATIONS ##     
    def permute(self, table, srcWidth, src):
        dst = 0
        for i in range(0,len(table)):
            srcPos = srcWidth - table[i]
            dst = (dst<<1) | (src>>srcPos & 0x01)    
        return dst


    ## IMPLEMENTATION OF SUBSTITUTION PERMUTATION ##
    def S_f(self, boxNumber, src):
        src = src&0x20 | ((src&0x01)<<4) | ((src&0x1E)>>1)
        return self.S[boxNumber-1][src]


    ## IMPLEMENATION OF FEISTEL CIPHER ##
    def feistel(self, r, subkey):
        e = self.E_f(r)
        x = e ^ subkey
        dst = 0
        for i in range(0,8):
            dst >>= 4
            s = self.S_f(8-i, (x&0x3F))
            dst |= s << 28
            x>>=6
        return self.P_f(dst)


    ## SUBKEY GENERATION ##    
    def createSubkeys(self, key):   
        key = self.PC1_f(key)
        c = key>>28
        d = key&0x0FFFFFFF        
        subkeys = [0 for x in xrange(16)]
        for i in range (0,16):
            if (self.rotations[i] == 1):
                c = ((c<<1) & 0x0FFFFFFF) | (c>>27)
                d = ((d<<1) & 0x0FFFFFFF) | (d>>27)
            else:
                c = ((c<<2) & 0x0FFFFFFF) | (c>>26)
                d = ((d<<2) & 0x0FFFFFFF) | (d>>26)
            
            cd = (c&0xFFFFFFFF)<<28 | (d&0xFFFFFFFF)
            subkeys[i] = self.PC2_f(cd)
        self.tmp=subkeys 
        return subkeys

    



class des():

    def __init__(self):
        self.cipher = []
        self.o = base_des()

    ## ENCRYPTS EACH 8-BYTE BLOCK OF MESSAGE TO 8-BYTE CIPHERTEXT ## 
    def encryptBlock(self, message, messageOffset, key, cipherOffset):
        def convertToLong(ba, offset):
            l = 0; 
            for i in range (0,8):
                if ((offset + i) < len(ba)) : value = ba[offset+i]
                else: value = 0
                l = l<<8 | (value & 0xFF);       
            return l
 
        def convertFromLong(offset, l):
            ba = [0 for x in xrange(16)]
            for i in range(7,-1,-1):
                if ((offset + i) < len(ba)):
                    ba[offset+i] = (l & 0xFF)
                    l = l >> 8
                else: break
            return ba

        def en(m, key):
            ## 
            subkeys = self.o.createSubkeys(key) if not self.o.decrypt else self.o.tmp  
            ip = self.o.IP_f(m)        
            l = ip>>32
            r = ip&0xFFFFFFFF
            #print subkeys        
            for i in range(0,16):
                previous_l = l
                l = r                
                r = previous_l ^ self.o.feistel(r, subkeys[i])                
            rl = (r&0xFFFFFFFF)<<32 | (l&0xFFFFFFFF)        
            fp = self.o.FP_f(rl)
                 
            return fp
  

        
        m = convertToLong(message, messageOffset)
        k = convertToLong(key, 0) 
        c = en(m, k)
        self.cipher.extend(convertFromLong(cipherOffset, c))



    def encrypt(self, text, passwd):
        def rshift(val, n): 
            return val>>n if val >= 0 else (val+0x100000000)>>n

        def add_text_pad(text):
            text_array = list(bytearray(text))
            length = len(text_array)
            text_pad = int(self.o.text_pad, 2)
            while (length % 8) != 0:
               text_array.append(text_pad)
               length += 1
            return text_array

        def passToKey(passwd):
            pw_array = list(bytearray(passwd))
            key = []
            for i in range (0,8):
                if i < len(pw_array):
                    b = pw_array[i]
                    b2 = 0
                    for j in range (0,8):
                        b2 <<= 1
                        b2 |= (b&0x1)
                        b >>=1    
                    key.append(b2)

                else:
                    key.append(int(self.o.key_pad, 2))

            return key 
              

        if not self.o.decrypt: 
            text_array = add_text_pad(text)
            #print text_array

        else: text_array =text

        key = passToKey(passwd)
        #print key

        i = 0  
        while i < len(text_array):
            self.encryptBlock(text_array, i, key, i)
            i += 8          
         
        cipher = [] 
        for x in self.cipher:
            if x:
                cipher.append(int(x))
                 
        self.cipher = []
        if not self.o.decrypt: 
            for i in range(0,8):
                k=self.o.tmp[i]
    	        self.o.tmp[i]=self.o.tmp[15-i]
                self.o.tmp[15-i]=k 

    	    self.o.decrypt = True   
        return cipher


if __name__ == '__main__':

    obj = des()
    if sys.argv[2:]:
        text = sys.argv[1]
        key = sys.argv[2]
        e = obj.encrypt(text, key)
        cipher = ''.join(list(map(hex,e))) 
        print "Encrypted:"
        print cipher
       
        d = obj.encrypt(e, key)
        str = "" 
        for x in d:
            if x <> 129: 
                str = str + (unichr(x))
        print "Decrypted"
        print str 

    else:
        print "Usage:<filename><plaintext><key>"
        

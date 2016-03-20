########## IMPLEMENTATION OF AES-128 ##############

import sys
from copy import copy


class base_aes(object):



    ## Rijndael S-box ##
    Sbox = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]


    ## Rijndael Inverted S-box ##
    InvSbox = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]



    ## Rijndael Rcon ##
    Rcon = [
           0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
           0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
           0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
           0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39]


    ## Adds (XORs) the round key to the state MATRIX ##
    def add_round_key(self, state, roundKey):
        for i in range(len(state)):
            for j in range(len(state)): 
                state[i][j] = state[i][j] ^ roundKey[i][j]

 
 
    ## substitute all the values from the state with the value in the SBox
    ## using the state value as index for the SBox ##
    def sub_bytes(self, state):
        for i in range(len(state)):
            for j in range(len(state)):
                state[i][j] = self.Sbox[state[i][j]]


    def inv_sub_bytes(self, state):
        for i in range(len(state)):
            for j in range(len(state)):
                state[i][j] = self.InvSbox[state[i][j]]


    ## iterate over each "virtual" row in the state table and shift the bytes
    ## to the LEFT by the appropriate offset ##

    def rotate(self,word, n):
        return word[n:]+word[0:n]

    def shift_rows(self,state):
        for i in range(4):
            state[i*4:i*4+4] = self.rotate(state[i*4:i*4+4],i)

    def inv_shift_rows(self,state):
        for i in range(4):
            state[i*4:i*4+4] = self.rotate(state[i*4:i*4+4],-i)



    ## learnt from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c ##
    def times(self, c):
        if (c & 0x80): 
            return (((c << 1) ^ 0x1B) & 0xFF)

        else:
            return (c << 1)
        


    ## Galois Multiplication ##
    def galoisMult(self, a, b):
        p = 0
        hiBitSet = 0
        for i in range(8):
            if b & 1 == 1:
                p ^= a
            hiBitSet = a & 0x80
            a <<= 1
            if hiBitSet == 0x80:
                a ^= 0x1b
            b >>= 1
        return p % 256

    ## mixColumn takes a column and performs the mixcolumn function of AES ##
    def mix_single_column(self, column):
        temp = copy(column)
        column[0] = self.galoisMult(temp[0],2) ^ self.galoisMult(temp[3],1) ^ \
                    self.galoisMult(temp[2],1) ^ self.galoisMult(temp[1],3)
        column[1] = self.galoisMult(temp[1],2) ^ self.galoisMult(temp[0],1) ^ \
                    self.galoisMult(temp[3],1) ^ self.galoisMult(temp[2],3)
        column[2] = self.galoisMult(temp[2],2) ^ self.galoisMult(temp[1],1) ^ \
                    self.galoisMult(temp[0],1) ^ self.galoisMult(temp[3],3)
        column[3] = self.galoisMult(temp[3],2) ^ self.galoisMult(temp[2],1) ^ \
                    self.galoisMult(temp[1],1) ^ self.galoisMult(temp[0],3)
 


    def mix_columns(self, state):
        for i in range(4):
            self.mix_single_column(state[i])


    def inv_mix_columns(self,s):
        for i in range(4):
            u = self.times(self.times(s[i][0] ^ s[i][2]))
            v = self.times(self.times(s[i][1] ^ s[i][3]))
            s[i][0] ^= u
            s[i][1] ^= v
            s[i][2] ^= u
            s[i][3] ^= v

        self.mix_columns(s)


    # round_encrypt applies each of the four transformations in order ##  
    def round_encrypt(self,state_matrix, key_matrix):
        self.sub_bytes(state_matrix)
        self.shift_rows(state_matrix)
        self.mix_columns(state_matrix)
        self.add_round_key(state_matrix, key_matrix)


    ## round_decrypt applies each of the four transformations in order ## 
    def round_decrypt(self,state_matrix, key_matrix):
        self.add_round_key(state_matrix, key_matrix)
        self.inv_mix_columns(state_matrix)
        self.inv_shift_rows(state_matrix)
        self.inv_sub_bytes(state_matrix)


    ## converts the input text into corresponding matrix ## 
    def textToMatrix(self,text):
        matrix = []
        for i in range(16):
            byte = (text >> (8 * (15 - i))) & 0xFF
            if i % 4 == 0:
                matrix.append([byte])
            else:
                matrix[i / 4].append(byte)
        return matrix


    ## converts the input matrix into corresponding text ## 
    def matrixToText(self, matrix):
        text = 0
        for i in range(4):
            for j in range(4):
                text |= (matrix[i][j] << (120 - 8 * (4 * i + j)))
        return text



class aes:



    def __init__(self, master_key):
        self.o = base_aes()
        self.change_key(master_key)



    def change_key(self, master_key):
        self.round_keys = self.o.textToMatrix(master_key)
        ##print self.round_keys

        for i in range(4, 4 * 11):
            self.round_keys.append([])
            if i % 4 == 0:
                byte = self.round_keys[i - 4][0]        \
                     ^ self.o.Sbox[self.round_keys[i - 1][1]]  \
                     ^ self.o.Rcon[i / 4]
                self.round_keys[i].append(byte)

                for j in range(1, 4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ self.o.Sbox[self.round_keys[i - 1][(j + 1) % 4]]
                    self.round_keys[i].append(byte)
            else:
                for j in range(4):
                    byte = self.round_keys[i - 4][j]    \
                         ^ self.round_keys[i - 1][j]
                    self.round_keys[i].append(byte)


        

    def encrypt(self, plaintext):
        self.plain_state = self.o.textToMatrix(plaintext)

        self.o.add_round_key(self.plain_state, self.round_keys[:4])

        for i in range(1, 10):
            self.o.round_encrypt(self.plain_state, self.round_keys[4 * i : 4 * (i + 1)])

        self.o.sub_bytes(self.plain_state)
        self.o.shift_rows(self.plain_state)
        self.o.add_round_key(self.plain_state, self.round_keys[40:])

        return self.o.matrixToText(self.plain_state)




    def decrypt(self, ciphertext):
        self.cipher_state = self.o.textToMatrix(ciphertext)

        self.o.add_round_key(self.cipher_state, self.round_keys[40:])
        self.o.inv_shift_rows(self.cipher_state)
        self.o.inv_sub_bytes(self.cipher_state)

        for i in range(9, 0, -1):
            self.o.round_decrypt(self.cipher_state, self.round_keys[4 * i : 4 * (i + 1)])

        self.o.add_round_key(self.cipher_state, self.round_keys[:4])

        return self.o.matrixToText(self.cipher_state)



if __name__ == '__main__':

    
    plaintext = 0x3243f6a8885a308d313198a2e0370734
    key = 0x2b7e151628aed2a6abf7158809cf4f3c

    obj = aes(key)


    encrypted = obj.encrypt(plaintext)
    decrypted = obj.decrypt(encrypted)

    print 'plaintext:', hex(plaintext)
    print 'masterkey:', hex(key)

    print 'encrypted:', hex(encrypted)

    print 'decrypted:', hex(decrypted)
    
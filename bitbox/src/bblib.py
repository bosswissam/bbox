#!/usr/bin/env python3

"""
    An implementation of the Shen-Shi-Waters predicate encryption scheme with a
    chain block cipher encryption/decryption mode.

    Copyright (C) 2011
      Scott Bezek, Wissam Jarjoui, Di Liu, Michael Morris-Pearce

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>
"""

from pypbc import *

import math
import random
import sys
import time

SECURITY = 100
PRIME_BITS = 256
VERSION_STRING = "0.3"
BLOCK_SIZE = 16
KEY_SIZE = 256

class Ciphertext:
    CPrime = None
    C = None
    C0 = None
    Cs = None

    def __init__(self, CPrime, C, C0, Cs):
        self.CPrime = CPrime
        self.C = C
        self.C0 = C0
        self.Cs = Cs

    def __str__(self):
        s = ""
        s += str(self.CPrime) + "\n"
        s += str(self.C) + "\n"
        s += str(self.C0) + "\n"
        s += str(len(self.Cs)) + "\n"
        for c in self.Cs:
            s += str(c[0]) + "\n"
            s += str(c[1]) + "\n"
        return s

    @classmethod
    def fromStr(cls, pairing, s):
        lines = s.splitlines()
        
        str_CPrime = lines.pop(0)
        CPrime = Element(pairing, GT)
        CPrime.input_value(str_CPrime)

        str_C = lines.pop(0)
        C = Element(pairing, G1)
        C.input_value(str_C)

        str_C0 = lines.pop(0) 
        C0 = Element(pairing, G1)
        C0.input_value(str_C0)

        securityParam = int(lines.pop(0))
        Cs = []
        for i in range(securityParam):
            str_C_1 = lines.pop(0)
            C_1 = Element(pairing, G1)
            C_1.input_value(str_C_1)

            str_C_2 = lines.pop(0)
            C_2 = Element(pairing, G1)
            C_2.input_value(str_C_2)

            Cs.append((C_1,C_2))

        return cls(CPrime, C, C0, Cs) 

class Token:
    K = None
    K0 = None
    Ks = None

    def __init__(self, K, K0, Ks):
        self.K = K
        self.K0 = K0
        self.Ks = Ks

    def __str__(self):
        s = ""
        s += str(self.K) + "\n"
        s += str(self.K0) + "\n"
        s += str(len(self.Ks)) + "\n"
        for k in self.Ks:
            s += str(k[0]) + "\n"
            s += str(k[1]) + "\n"
        return s

    @classmethod
    def fromStr(cls, pairing, s):
        lines = s.splitlines()
        str_K = lines.pop(0)
        K = Element(pairing, G1)
        K.input_value(str_K)

        str_K0 = lines.pop(0)
        K0 = Element(pairing, G1)
        K0.input_value(str_K0)

        securityParam = int(lines.pop(0))
        Ks = []
        for i in range(securityParam):
            str_K_1 = lines.pop(0)
            K_1 = Element(pairing, G1)
            K_1.input_value(str_K_1)

            str_K_2 = lines.pop(0)
            K_2 = Element(pairing, G1)
            K_2.input_value(str_K_2)

            Ks.append((K_1,K_2))

        return cls(K, K0, Ks) 

class SecretKey:
    g_G_p = None
    g_G_q = None
    g_G_r = None
    g_G_s = None
    hs = None
    us = None
    h_gamma = None
    P = None
    def __init__(self, g_G_p, g_G_q, g_G_r, g_G_s, hs, us, h_gamma, P):
        self.g_G_p = g_G_p
        self.g_G_q = g_G_q
        self.g_G_r = g_G_r
        self.g_G_s = g_G_s
        self.hs = hs
        self.us = us
        self.h_gamma = h_gamma
        self.P = P

    def __str__(self): 
        s = ""
        s += str(self.g_G_p) + "\n"
        s += str(self.g_G_q) + "\n"
        s += str(self.g_G_r) + "\n"
        s += str(self.g_G_s) + "\n"
        s += str(len(self.hs)) + "\n"
        
        for (h1,h2) in self.hs:
            s += str(h1) + "\n"
            s += str(h2) + "\n"
        for (u1,u2) in self.us:
            s += str(u1) + "\n"
            s += str(u2) + "\n"
        s += str(self.h_gamma) + "\n"
        s += str(self.P) + "\n"
        
        return s

    @classmethod
    def fromStr(cls, pairing, s):
        lines = s.splitlines()
        str_g_G_p = lines.pop(0)
        g_G_p = Element(pairing, G1)
        g_G_p.input_value(str_g_G_p)

        str_g_G_q = lines.pop(0)
        g_G_q = Element(pairing, G1)
        g_G_q.input_value(str_g_G_q)

        str_g_G_r = lines.pop(0)
        g_G_r = Element(pairing, G1)
        g_G_r.input_value(str_g_G_r)
        
        str_g_G_s = lines.pop(0)
        g_G_s = Element(pairing, G1)
        g_G_s.input_value(str_g_G_s)

        securityParam = int(lines.pop(0))

        hs = []
        us = []
        for i in range(securityParam):
            str_h_1 = lines.pop(0)
            h_1 = Element(pairing, G1)
            h_1.input_value(str_h_1)

            str_h_2 = lines.pop(0)
            h_2 = Element(pairing, G1)
            h_2.input_value(str_h_2)

            hs.append((h_1,h_2))

        for i in range(securityParam):
            str_u_1 = lines.pop(0)
            u_1 = Element(pairing, G1)
            u_1.input_value(str_u_1)

            str_u_2 = lines.pop(0)
            u_2 = Element(pairing, G1)
            u_2.input_value(str_u_2)
            
            us.append((u_1,u_2))

        str_h_gamma = lines.pop(0)
        h_gamma = Element(pairing, G1)
        h_gamma.input_value(str_h_gamma)

        str_P = lines.pop(0)
        P = Element(pairing, GT)
        P.input_value(str_P)

        return cls( g_G_p, g_G_q, g_G_r, g_G_s, hs, us, h_gamma, P)

class Cryptosystem:
    def __init__(self, security, pairing, params, sk, g_GT, dlog, tags, \
        strength):
        if (strength is not None):
            self.prime_bits = strength
        else:
            self.prime_bits = PRIME_BITS
        self.security = security
        self.pairing = pairing
        self.params = params
        self.sk = sk
        self.g_GT = g_GT
        self.dlog = dlog
        self.tags = tags

    # Make sure everything is ready to use the Cryptosystem
    def checkBase(self):
        if self.security is None:
            raise Exception("Missing security parameter")

        if self.pairing is None:
            raise Exception("Missing pairing (did you remember to load the pairing params file?)")

        if self.params is None:
            raise Exception("Missing pairing params (did you remember to load the pairing params file?)")

        if not self.g_GT:
            raise Exception("Missing g_GT")

    def checkEncrypt(self):
        if self.sk is None:
            raise Exception("Missing master secret key")

        if not self.tags or len(self.tags) == 0:
            raise Exception("Missing tokens")

    def checkDecrypt(self):
        if not self.tags or len(self.tags) == 0:
            raise Exception("Missing tokens")

    @classmethod
    def new(cls, securityParam, strength):
        if (strength is not None):
            prime_bits = strength
        else:
            prime_bits = PRIME_BITS
    
        # Select p, q, r, s
        p = get_random_prime(prime_bits)
        q = get_random_prime(prime_bits)
        r = get_random_prime(prime_bits)
        s = get_random_prime(prime_bits)
        
        # Make n
        n = p*q*r*s
        
        # Build the params
        params = Parameters(n=n)
        
        # Build the pairing
        pairing = Pairing(params)
        
        # Find the generators for the G_p, G_q, G_r, and G_s subgroups
        g_G_p = Element.random(pairing, G1)**(q*r*s)
        g_G_r = Element.random(pairing, G1)**(p*q*s)
        g_G_q = Element.random(pairing, G1)**(p*r*s)
        g_G_s = Element.random(pairing, G1)**(p*r*q)
        
        # Choose the random h's and u's
        hs = []
        us = []
        for i in range(securityParam):
            hs.append((g_G_p**Element.random(pairing, Zr), \
                g_G_p**Element.random(pairing, Zr)))
            us.append((g_G_p**Element.random(pairing, Zr), \
                g_G_p**Element.random(pairing, Zr)))
            sys.stdout.write('.')
            sys.stdout.flush()
        sys.stdout.write('\n')
        
        # Choose gamma and create P, used for decryption
        gamma = Element(pairing, Zr, get_random(p))
        h = g_G_p ** Element.random(pairing, Zr)
        P = pairing.apply(g_G_p,h) ** gamma
        h_gamma = h ** (-gamma)
        sk = SecretKey(g_G_p, g_G_q, g_G_r, g_G_s, hs, us, h_gamma, P)
        g_GT = pairing.apply(g_G_p,g_G_p) 
        tags = {}
        return cls(securityParam, pairing, params, sk, g_GT, None, tags, \
            strength)

    def getSecrets(self):
        s = ""
        s += "-----BEGIN SK-----\n"
        s += str(self.sk) + "\n"
        s += "-----END SK-----\n"

        # Write tags/tokens
        s += str(len(self.tags)) + "\n"
        for (tag, (token, uid)) in self.tags.items():
            s += str(tag) + "\n"
            s += str(token) #+ "\n"
            s += "-----END TOKEN-----\n"
            s += str(uid) + "\n"
        return s

    def loadSecrets(self, string):
        lines = string.split("\\n")
        lines.pop(0)
        str_sk = ""
        temp_s = lines.pop(0)
        while temp_s != "-----END SK-----":
            str_sk += temp_s + "\n"
            temp_s = lines.pop(0)
        if str_sk != "None\n":
            self.sk = SecretKey.fromStr(self.pairing, str_sk)

        # Read tags/tokens
        self.tags = {}
        numTags = int(lines.pop(0))
        for i in range(numTags):
            str_tag = lines.pop(0)
            str_token = ""
            temp_s = lines.pop(0)
            while temp_s != "-----END TOKEN-----":
                str_token += temp_s + "\n"
                temp_s = lines.pop(0)
            try:
                uid = int(lines.pop(0))
            except:
                uid = None
            self.tags[str_tag] = (Token.fromStr(self.pairing,str_token), uid)

    @classmethod
    def fromPairingFileAndString(cls, pairingFilename, string):
        #read the pairing params
        pairingFile = open(pairingFilename, 'r')
        s = pairingFile.read()
        params = Parameters(param_string=s)
        pairingFile.close()
        pairing = Pairing(params)
        lines = string.splitlines()
        securityParam = int(lines.pop(0))
        strength = int(lines.pop(0))
        str_g_GT = lines.pop(0)
        g_GT = Element(pairing, GT)
        g_GT.input_value(str_g_GT)
        tags = {}
        dlog = None
        return cls(securityParam, pairing, params, None, g_GT, dlog, tags, \
            strength)

    def exportPairingParams(self, pairingFilename):
        self.params.save(pairingFilename)

    def exportCryptoBasics(self):
        s = ""
        s += str(self.security) + "\n"
        s += str(self.prime_bits) + "\n"
        s += str(self.g_GT) + "\n"
        return s

    # Take a list of uids (random integers) and return a polynomial
    # acl of order security. We assume you have fewer than self.security uids
    # here.
    def uids_to_acl(self, uids):
        acl = [1]
        for u in uids:
            acl = self.polymult(acl,[-u,1])
        #keep in finite field of order n
        #acl = [a%1000000000000000 for a in acl] #TODO:fix badness
        acl.reverse()
        while len(acl)<self.security:
            acl.append(0)
        return acl

    # Arguments to polymult are polynomials, represented as arrays of
    # coefficients, where the lowest index corresponds to the lowest order
    # coefficient
    def polymult(self,a,b):
        prod = [0]*(len(a)+len(b)-1)
        for i in range(len(a)):
            for j in range(len(b)):
                prod[i+j]+=a[i]*b[j]
        return prod

    def createTag(self, tag):
        uid = random.randint(0 , 1000000000000000000) #TODO: Fix badness
        user_v = []
        for i in range(self.security):
            user_v.append(uid**(self.security - 1 - i))
        token = self.genToken(user_v)
        self.tags[tag] = (token, uid)

    def importTag(self, tag, token, uid=None):
        token = Token.fromStr(self.pairing, token)
        self.tags[tag] = (token, uid)

    def exportTag(self, tag):
        return str(self.tags[tag][0])

    def encryptWithTags(self, tags, msg):
        uids = []
        for t in tags:
            uids.append(self.tags[t][1])
        acl = self.uids_to_acl(uids)
        return self.cbc_enc(acl, msg)

    def decryptWithTag(self, tag, ciphertext):
        token = self.tags[tag][0]
        return self.cbc_dec(ciphertext, token)

    def genToken(self, v: "description of a predicate") -> "SK_f":
        self.checkBase()
        R = self.sk.g_G_r**Element.random(self.pairing, Zr)
        R0 = self.sk.g_G_r**Element.random(self.pairing, Zr)
        Rs = []
        for i in range(self.security):
                # Build r1
                r1 = Element.random(self.pairing, Zr)
                # Build r2
                r2 = Element.random(self.pairing, Zr)
                Rs.append((r1, r2))
        Ss = [(self.sk.g_G_s**Element.random(self.pairing, Zr), \
            self.sk.g_G_s**Element.random(self.pairing, Zr)) \
                for i in range(self.security)]
        f1 = Element.random(self.pairing, Zr)
        f2 = Element.random(self.pairing, Zr)
        K = R*self.sk.h_gamma
        K0 = R0*self.sk.h_gamma
        Ks = []
        for i in range(self.security):
            # Get h1, h2
            h1, h2 = self.sk.hs[i]
            
            # Get u1, u2
            u1, u2 = self.sk.us[i]
            
            # Get r1, r2, s1, s2
            r1, r2 = Rs[i]
            s1, s2 = Ss[i]
            
            # Form the intermediate value
            i1 = h1**(-r1)
            i2 = h2**(-r2)
            j1 = u1**(-r1)
            j2 = u2**(-r2)
            
            #TODO: Investigate potential bug?
            #      Ks = [] for pos in range(self.security):
            K *= i1 * i2 
            K0 *= j1 * j2
            K1 = (self.sk.g_G_p**r1) * (self.sk.g_G_q**(f1*v[i]) * s1)
            K2 = (self.sk.g_G_p**r2) * (self.sk.g_G_q**(f2*v[i]) * s2)
            Ks.append((K1, K2))
        return Token(K, K0, Ks)

    def encrypt(self, x: "vector of elements in Zr", \
        m: "element of Gt") -> "ciphertext":
        self.checkBase()
        self.checkEncrypt()
        M = (self.g_GT ** m)

        y = Element.random(self.pairing, Zr)
        z = Element.random(self.pairing, Zr)
        a = Element.random(self.pairing, Zr)
        b = Element.random(self.pairing, Zr)
        S = self.sk.g_G_s**Element.random(self.pairing, Zr)
        S0 = self.sk.g_G_s**Element.random(self.pairing, Zr)
        Rs = []
        for i in range(self.security):
                r1 = self.sk.g_G_r**Element.random(self.pairing, Zr)
                r2 = self.sk.g_G_r**Element.random(self.pairing, Zr)
                Rs.append((r1, r2))
        Cprime = M * (self.sk.P ** (y+z))
        C = S*self.sk.g_G_p**y
        C0 = S0*self.sk.g_G_p**z
        Cs = []
        for i in range(self.security):
                h1, h2 = self.sk.hs[i]
                u1, u2 = self.sk.us[i]
                i1 = self.sk.g_G_q**(a*x[i])
                i2 = self.sk.g_G_q**(b*x[i])
                c1 = h1**y * u1**z * i1 * Rs[i][0]
                c2 = h2**y * u2**z * i2 * Rs[i][1]
                Cs.append((c1, c2))
        return Ciphertext(Cprime, C, C0, Cs)

    def decrypt(self, c: "ciphertext", \
        sk_f: "secret key corresponding to predicate f") -> "message or T":
        self.checkBase()
        self.checkDecrypt()
        K = sk_f.K
        K0 = sk_f.K0
        Ks = sk_f.Ks
        output = c.CPrime * self.pairing.apply(c.C, K) \
            * self.pairing.apply(c.C0, K0)
        for i in range(self.security):
            j = self.pairing.apply(c.Cs[i][0], Ks[i][0])
            k = self.pairing.apply(c.Cs[i][1], Ks[i][1])
            temp = j*k
            temp2 = output * temp
            output = temp2
        return output

    def cbc_enc(self, x, M):
        self.checkBase()
        self.checkEncrypt()
        mask = (1 << BLOCK_SIZE)-1
        C = []
        C.append(self.encrypt(x, M & mask))
        for k in range(int(KEY_SIZE/BLOCK_SIZE) - 1):
            M = M >> BLOCK_SIZE
            m = M & mask
            (i,j) = str(C[k].CPrime)[1:-1].split(',')
            i = int(i) & mask
            c = self.encrypt(x, m^i)
            C.append(c)
        return C

    def cbc_dec(self, C, sk_f):
        self.checkBase()
        self.checkDecrypt()
        #print("Decrypting...", end="")
        sys.stdout.flush()
        mask = (1 << BLOCK_SIZE)-1
        M = []
        decrypted_block = self.lookup_dlog(str(self.decrypt(C[0], sk_f)))
        if decrypted_block is None:
            return None
        M.append(decrypted_block)
        for k in range(len(C)-1):
            #print(".", end="")
            sys.stdout.flush()
            (i,j) = str(C[k].CPrime)[1:-1].split(',')
            i = int(i) & mask
            decrypted_block = self.lookup_dlog(str(self.decrypt(C[k+1], \
                sk_f)))
            if decrypted_block is None:
                return None
            M.append(decrypted_block^i)
        i = len(M) -1
        x = 0
        while(i>=0):
            x = x | M[i]
            if (i > 0):
                x = x << BLOCK_SIZE
            i -= 1
        #print("[done]")
        return x
 
    def precompute_dlog(self):
        self.dlog = dict()
        i = 0
        while(i < 2**BLOCK_SIZE):
            self.dlog[str(self.g_GT**i)] = i
            i += 1

    def lookup_dlog(self, index):
        if not self.dlog:
            self.precompute_dlog()
        if index not in self.dlog.keys():
            return None
        return self.dlog[index]

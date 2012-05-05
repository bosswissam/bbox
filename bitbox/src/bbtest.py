def awesome_test():

  security = 10

  # build the polynomial vector
  file1_v = []
  file2_v = []
  file3_v = []
  for i in range(security):
    file1_v.append(0)
    file2_v.append(0)
    file3_v.append(0)
  file1_v[0] = 1
  file1_v[1] = -27
  file1_v[2] = 152
  file2_v[0] = 1
  file2_v[1] = -27
  file2_v[2] = 140
  file3_v[0] = 1
  file3_v[1] = -39
  file3_v[2] = 380

  # build the X vector
  user1_v = []
  user2_v = []
  for i in range(security):
	  user1_v.append(19**(security - 1 - i))
	  user2_v.append(20**(security - 1 - i))

  #print("setting up cryptosystem...")
  #print(time.time())
  # done with the proof, test the cryptosystem against it
  c = Cryptosystem.new(security)
  c.save("testSystem")
  #c2.save("testSystemClone")

  # build the secret key corresponding to the above polynomial
  #print("generating keys...")
  #print(time.time())
  print("1")
  skf = c.genToken(user1_v)
  print("2")
  skf2 = c.genToken(user2_v)

  skf.save("testing123")
  skf2.save("testing1232")
  skf = None
  skf2 = None
  #print("picking ...")
  #print(time.time())
  # encrypt the value given
  #m = c.pairing.apply(Element.random(c.pairing, G1), Element.random(c.pairing,G1))
  m = 0xff00ff01ff02ff03ff04ff05ff06ff07ff08ff09ff0aff0bff0cff0dff0eff0f
  
#print(M)

  #print("g_p: ", c.sk.g_G_p)
  c.sk.g_G_p.output_value("output.out")
  c.sk.g_G_p = None
  #print("g_p: ", c.sk.g_G_p)
  f = open("output.out")
  s = f.read()
  c.sk.g_G_p = Element(c.pairing, G1)
  c.sk.g_G_p.input_value(s)
  f.close()
  #print("g_p: ", c.sk.g_G_p)

##  e1 = c.encrypt(file1_v, M)
##  e2 = c.encrypt(file2_v, M)
##  e3 = c.encrypt(file3_v, M)

  e1 = c.cbc_enc(file1_v, m)
  e2 = c.cbc_enc(file2_v, m)
  e3 = c.cbc_enc(file3_v, m)

  #c = None 
  #c = Cryptosystem.fromFile("testSystem",False)

  skf = Token.fromFile(c.pairing,"testing123")
  skf2 = Token.fromFile(c.pairing,"testing1232")

  # decrypt it
  print("file 1")
  #print(time.time())
  m1 = c.cbc_dec(e1, skf)
  m2 = c.cbc_dec(e1, skf2)

##  m1 = c.decrypt(e1, skf)
##  m2 = c.decrypt(e1, skf2)
  print('%x' % m1)
  assert(M == m1)
  assert(M != m2)
  assert(m1 != m2)
  
  print("file 2")

  m1 = c.cbc_dec(e2, skf)
  #m1 = c.decrypt(e2, skf)
  print("decrypted 1")
  m2 = c.cbc_dec(e2, skf2)
  print("decrypted 2")

  assert(M == m2)
  print("asserted 1")
  assert(M != m1)
  print("asserted 2")
  assert(m1 != m2)

  print("file 3")
  m1 = c.cbc_dec(e3, skf)
  m2 = c.cbc_dec(e3, skf2)
  assert(M == m1 == m2)

  print("done")

# time encrypt + decrypte for security param
def time_system(security):
  # build the polynomial vector
  file1_v = []
  for i in range(security):
    file1_v.append(0)
  file1_v[0] = 1
  file1_v[1] = -27
  file1_v[2] = 152

  # build the X vector
  user1_v = []
  for i in range(security):
	  user1_v.append(19**(security - 1 - i))

  t_a = time.time()
  c = Cryptosystem.new(security)
  
  t_b = time.time()
  skf = c.genToken(user1_v)
  t_c = time.time()

  # set up message
  g_GT = c.pairing.apply(c.sk.g_G_p,c.sk.g_G_p) 
  m = Element(c.pairing,Zr,497930)
  M = (g_GT ** m)
  e1 = c.encrypt(file1_v, M)
  t_d = time.time()

  m1 = c.decrypt(e1, skf)

  t_e = time.time()
  assert(M == m1)

  return (t_b-t_a, t_c-t_b, t_d-t_c, t_e-t_d)

def time_test():
  print("securityParam,setup,gentoken,encrypt,decrypt")
  for x in range(10, 1000, 10):
    results = time_system(x)
    print("%i,%f,%f,%f,%f" % (x,results[0],results[1],results[2],results[3]))

if __name__ == "__main__":
    awesome_test()

#!/usr/bin/env python3

# Copyright 2019 Paul Dworzanski
# TODO: Choose an open-source license

# This closely follows Appendix B of yellowpaper

debug = 0

# main functions for encoding (RPL) and decoding (RLP_inv)
def RLP(x):
  if debug: print("RLP(",x,")")
  if type(x) in {bytearray,bytes}:
    return R_b(x)
  elif type(x)==int:
    return RLP(BE(x))
  else: #list
    return R_l(x)

def RLP_inv(b):
  if debug: print("RLP_inv(",b,")")
  if len(b)==0:
    return bytearray([0x80])
  if b[0]<0xc0: # bytes
    return R_b_inv(b)
  else:
    return R_l_inv(b)

# binary encoding/decoding
def R_b(x):
  if debug: print("R_b(",x,")")
  if len(x)==1 and x[0]<128:
    return x #bytearray([x[0] + 0x80])
  elif len(x)<56:
    return bytearray([128+len(x)])+x
  else:
    #print(len(BE(len(x))), BE(len(x)) , x)
    return bytearray([ 183+len(BE(len(x))) ]) + BE(len(x))  + x

def R_b_inv(b):
  if debug: print("R_b_inv(",b,")")
  if len(b)==1 and b[0]<0x80:
    return b #bytearray([b[0]-0x80])
  elif b[0]<=0xb7:
    return b[1:1+b[0]-0x80]
  else:
    len_BElenx = b[0] - 183
    lenx = BE_inv(b[1:len_BElenx+1]) #TODO lenx unused
    return b[len_BElenx+1:len_BElenx+1+lenx]


# big-endian
def BE(x):
  if debug: print("BE(",x,")")
  if x==0:
    return bytearray([0])
  ret = bytearray([])
  while x>0:
    ret = bytearray([x%256]) + ret
    x=x//256
  return ret

def BE_inv(b):
  if debug: print("BE_inv(",b,")")
  x=0
  for n in range(len(b)):
    x+=b[n]*2**(len(b)-1-n)
  return x

# list encoding/decoding
def R_l(x):
  if debug: print("R_l(",x,")")
  sx=s(x)
  if len(sx)<56:
    return bytearray([192+len(sx)]) + sx
  else:
    return bytearray([ 247+len(BE(len(sx))) , BE(len(sx)) ]) + sx

def R_l_inv(b):
  if debug: print("R_l_inv(",b,")")
  if b[0] <= 0xf7:
    lensx = b[0]-0xc0
    sx = b[1:1+lensx]
  else:
    len_lensx = b[0] - 247
    lensx = BE_inv(b[1:1+len_lensx])
    sx = b[1+len_lensx : 1+len_lensx+lensx]
  return s_inv(sx)

# for a list, recursively call RLP or RLP_inv
def s(x):
  if debug: print("s(",x,")")
  sx = bytearray([])
  for xi in x:
    sx+=RLP(xi)
  return sx

def s_inv(b):
  if debug: print("s_inv(",b,")")
  x=[]
  i=0
  len_=len(b)
  while i<len_:
    len_cur, len_len_cur = decode_length(b[i:])
    #print("  s_inv len_cur",len_cur,"b_cur",b[i:1+i+len_len_cur+len_cur])
    x += [RLP_inv(b[i:1+i+len_len_cur+len_cur])]
    i += len_cur + len_len_cur
    if debug: print("  s_inv() returning",x)
  if debug: print("  s_inv() returning",x)
  return x


# this is a helper function not described in the spec
# but the spec does not discuss the inverse to he RLP function, so never has the opportunity to discuss this
# returns the length of an encoded rlp object
def decode_length(b):
  if debug: print("length_inv(",b,")")
  if len(b)==0:
    return 0,0 # TODO: this may be an error
  length_length=0
  first_rlp_byte = b[0]
  if first_rlp_byte < 0x80:
    rlp_length=1
  elif first_rlp_byte <= 0xb7:
    rlp_length = first_rlp_byte - 0x80
  elif first_rlp_byte <= 0xbf:
    length_length = first_rlp_byte - 0xb7
    rlp_length = BE_inv(b[1:1+length_length])
  elif first_rlp_byte <= 0xf7:
    rlp_length = first_rlp_byte - 0xc0
  elif first_rlp_byte <= 0xbf:
    length_length = first_rlp_byte - 0xb7
    rlp_length = BE_inv(b[1:1+length_length])
  return rlp_length, 1+length_length



def test_RLP():
  # tests cases from here: https://github.com/ethereum/wiki/wiki/RLP
  test_cases = [
    ["dog".encode(),bytearray([0x83,ord('d'),ord('o'),ord('g')])],
    [[ "cat".encode(), "dog".encode() ], bytearray([ 0xc8, 0x83, ord('c'), ord('a'), ord('t'), 0x83, ord('d'), ord('o'), ord('g') ])],
    [bytearray([]), bytearray([0x80])],
    [[], b'\xc0'],
    #[bytearray([0x00]), bytearray([0x80])],
    [bytearray([0x0f]), bytearray([0x0f])],
    [bytearray([0x04,0x00]), bytearray([ 0x82, 0x04, 0x00 ])],
    [[ [], [[]], [ [], [[]] ] ], bytearray([ 0xc7, 0xc0, 0xc1, 0xc0, 0xc3, 0xc0, 0xc1, 0xc0 ])],
    ["Lorem ipsum dolor sit amet, consectetur adipisicing elit".encode(), bytearray(b'\xb88Lorem ipsum dolor sit amet, consectetur adipisicing elit')]
   ]
  for test in test_cases:
    #print("test",test)
    if RLP(test[0]) != test[1]:
      print("failed test RLP",test,RLP(test[0]))
    #else:
    #  print("passed test RLP",test)
    if test[0] != RLP_inv(test[1]):
      print("failed test RLP_inv",test,RLP_inv(test[1]))
    #else:
    #  print("passed test RLP_inv",test)







if __name__ == "__main__":
  test_RLP()
 

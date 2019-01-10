
# Copyright 2019 Paul Dworzanski
# TODO: Choose an open-source license

# This closely follows Appendix B of yellowpaper

def RLP(x):
  if type(x) in {bytearray,bytes}:
    return R_b(x)
  elif type(x)==int:
    return RLP(BE(x))
  else: #list
    return R_l(x)

def RLP_inv(b,type_):
  if type_=="b":
    return R_b_inv(b)
  elif type_=="n":
    return BE_inv(RLP_inv(b,"b"))
  else:
    return R_l_inv(b)


def R_b(x):
  if len(x)==1 and x[0]<128:
    return x
  elif len(x)<56:
    return bytearray([128+len(x)])+x
  else:
    return bytearray([ 183+len(BE(len(x))), BE(len(x)) ]) + x

def R_b_inv(b):
  if len(b)==1:
    return b[0]
  elif b[0]<184:
    return b[1:]
  else:
    len_BElenx = b[0] - 183
    lenx = BE_inv(b[1:len_BElenx+1]) #TODO lenx unused
    return b[len_BElenx+1:len_BElenx+1+lenx]


def BE(x):
  ret = bytearray([])
  while x>0:
    ret = bytearray([x%256]) + ret
    x=x//256
  return ret

def BE_inv(b):
  x=0
  for n in len(b):
    x+=ba[n]*2**(len(b)-1-n)
  return x


def R_l(x):
  sx=s(x)
  if len(sx)<56:
    return bytearray([192+len(sx)]) + sx
  else:
    return bytearray([ 247+len(BE(len(sx))) , BE(len(sx)) ]) + sx

def R_l_inv(b):
  if b[0] < 248:
    lensx = b[0]-192
    sx = b[1:]
  else:
    len_BElensx = b[0] - 247
    lensx = BE_inv(b[1:len_BElensx+1])
    sx = BE_inv(b[lenBElensx+1:lenBElenssx+1+lensx])
  return s_inv(sx)


def s(x):
  sx = bytearray([])
  for xi in x:
    sx+=RLP(xi)
  return sx

def s_inv(b):
  x=[]
  i=0
  while i<len(b):
    x += [RLP_inv(b)]
    i += len(x[-1]) #TODO: check this
  return x


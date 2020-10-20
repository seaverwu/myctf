
# This file was *autogenerated* from the file exp.sage
from sage.all_cmdline import *   # import sage library

_sage_const_7654319 = Integer(7654319); _sage_const_5081741 = Integer(5081741); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_2287747 = Integer(2287747); _sage_const_1424308 = Integer(1424308); _sage_const_1234577 = Integer(1234577); _sage_const_2366653 = Integer(2366653); _sage_const_5234568 = Integer(5234568); _sage_const_6744615 = Integer(6744615); _sage_const_610619 = Integer(610619); _sage_const_3213242 = Integer(3213242); _sage_const_6218 = Integer(6218)
a = _sage_const_1234577 
b = _sage_const_3213242 
n = _sage_const_7654319 

E = EllipticCurve(GF(n), [_sage_const_0 , _sage_const_0 , _sage_const_0 , a, b])

base = E([_sage_const_5234568 , _sage_const_2287747 ])
pub = E([_sage_const_2366653 , _sage_const_1424308 ])

c1 = E([_sage_const_5081741 , _sage_const_6744615 ])
c2 = E([_sage_const_610619 , _sage_const_6218 ])

X = base

for i in range(_sage_const_1 , n):
    if X == pub:
        secret = i
        print "[+] secret:", i
        break
    else:
        X = X + base
        print i

m = c2 - (c1 * secret)

print "[+] x:", m[_sage_const_0 ]
print "[+] y:", m[_sage_const_1 ]
print "[+] x+y:", m[_sage_const_0 ] + m[_sage_const_1 ]

# [+] x+y: 5720914


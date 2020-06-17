Hex = lambda x : list(map(hex,x.polynomial()))
HEX = lambda x : list(map(Hex,x))
Radix = lambda x,b: list(map(hex,ZZ(x).digits(b)))

bls12_prime = lambda t: ZZ((t-1)**2*(t**4-t**2+1)/3+t)
bls12_order = lambda t: ZZ(t**4-t**2+1)
g1_h = lambda t: ZZ(((t-1)**2) // 3)
g2_h = lambda t: ZZ(((t**8) - (4 * (t**7)) + (5 * (t**6)) - (4 * (t**4)) + (6 * (t**3)) - (4 * (t**2)) - (4*t) + 13) // 9)

bls12_x = -0xd201000000010000 # parameter
p = bls12_prime(bls12_x) # prime modulus
r = bls12_order(bls12_x) # prime order
F = GF(p)          # Base field
k = 12             # embedding degree
d = 6              # twist degree
# F2.<U> = GF(p**2, modulus=[1,0,1]) # t^2+1
# F2.<X>  = GF(p**2, modulus=t**2+1,        name='X',proof=false)
# F6.<Y>  = GF(p**6, modulus=t**6-2*t**3+2, name='Y',proof=false)
# F12.<Z> = GF(p**12,modulus=t**12-2*t**6+2,name='Z',proof=false)

K2.<x> = PolynomialRing(F)
F2.<u> = F.extension(x^2+1)
K6.<y> = PolynomialRing(F2)
F6.<v> = F2.extension(y^3 - (u+1))
K12.<z> = PolynomialRing(F6)
Ipol = z^2-v
Ipol.is_irreducible = lambda : true # shortcut to avoid expensive check
I = Ideal(Ipol)
# F12.<w> = F6.extension(z^2 - v) # Constructing this field takes long time.
F12.<w> = K12.quotient_by_principal_ideal(I)

g1_order = g1_h(bls12_x) * bls12_order(bls12_x)
g2_order = g2_h(bls12_x) * bls12_order(bls12_x)
g1_b = F(4)
g2_b = F2(4*(u+1))
G1 = EllipticCurve(F, [0,g1_b])
G2 = EllipticCurve(F2,[0,g2_b])
G2Full = EllipticCurve(F12,[0,g1_b])
GT = F12

def checks():
    assert G1.order() == g1_order, "order of G1 fail"
    assert G2.order() == g2_order, "order of G2 fail"
    assert is_prime(p),"p is not prime"
    assert is_prime(r),"r is not prime"
    assert (p**k-1)%(r**2) != 0,"r^2 divides p^k-1"
    print("checks: ok")


def TraceMap(P):
    x,y,z = P
    return sum([ G2Full([x**(p**i),y**(p**i)])  for i in range(k) ])

def checks():
    assert is_prime(p),"p is not prime"
    assert is_prime(r),"r is not prime"
    assert (p**k-1)%(r**2) != 0,"r^2 divides p^k-1"

def pair(P,Q):
    ''' calculates optimal ate pairing (P,Q) '''
    m = miller(u,P,Q)
    g = final_expo(m)
    return g

def l_TT(T,P):
    ''' line l_TT evaluated in P '''
    xp,yp,zp = P
    x,y,z = T
    return 3*x**2*xp-2*y*z*yp+3*E1_b*z**2-y**2

def l_TQ(T,Q,P):
    ''' line l_TQ evaluated in P '''
    xp,yp,zp = P
    xq,yq,zq = Q
    x,y,z = T
    return (x-z*yq)*(xq-xp)-(x-z*xq)*yq + (x-z*xq)*zq*yp

def miller(P,Q,u=bls12_x):
    ''' calculates f_(u,Q)(P) '''
    R = Q
    f = GT.one()
    for b in reversed(u.bits()[:-1]):
        R = 2*R
        f = f**2 * l_TT(R,P)
        if b == 1 :
            R = R + Q
            f = f * l_TQ(R,Q,P)
    return f

def final_expo(e):
    ''' raises e to (p^k-1)/r '''
    return e


# checks()

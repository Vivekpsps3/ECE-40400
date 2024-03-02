def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        # print("Bézout coefficients:", x, y)
        # print("greatest common divisor:", b)
        # print("quotients by the gcd:", u, v)
    gcd = b
    return gcd, x, y

if __name__ == "__main__":
    print(egcd(97,47))


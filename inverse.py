
def egcd(a,b):
	    if a == 0:
	        return b, 0, 1
	    else:
	        g, y, x = egcd(b % a, a)
	        return g, x - (b // a) * y, y

def modinv(a,p):
		if a < 0:
			return p - modinv(-a,p)
		g, x, y = egcd(a,p)
		if g != 1:
			print("les deux nombre ne sont pas premiers entre eux")
		else:
			return x % p

def binaryToDecimal(binary): 
      
    decimal, i, n = 0, 0, 0
    while(binary != 0):
    	if binary==2:
    		break 
        dec = binary % 10
        decimal = decimal + dec * pow(2, i) 
        binary = binary//10
        i += 1
    return decimal   

def decimalToBinary(x,n):
    return str(bin(x)[2:].zfill(n))

def convert(list): 
      
    # Converting integer list to string list 
    s = [str(i) for i in list] 
      
    # Join list items using join() 
    res ="".join(s)
      
    return(res) 


#print(chr(binaryToDecimal(int(decimalToBinary(101,5)))))

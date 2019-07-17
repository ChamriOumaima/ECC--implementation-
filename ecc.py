# -*- coding: utf-8 -*-
import tinyec.ec as ec
import tinyec.registry as reg
import random 
import math
import re
import os
import os.path
from inverse import *

class Pair:
	def __init__(self):
		self.x=0
		self.y=0

	def __repr__(self):
		return "("+str(self.x)+";"+str(self.y)+")"

		
class Personne:
	def __init__(self,name) :
		self.name=name
		self.privatek=0
		self.publick=Pair()
		self.secretk=Pair()
		self.courbe=0
		self.a=0
		self.b=0
		self.p=0
		self.g=Pair()
		self.field=0

	def defintionCourbe(self):
		self.courbe = reg.get_curve("secp192r1")

	
	def add(self,p,q,n):
		if p.x==0 and p.y==0 :
			return q
		if p.x!=q.x and p.y!=q.y :
			tmp=q.x-p.x
			temp=modinv(tmp,n)
			k=((q.y-p.y)*temp) % n
		else : 
			tmp=modinv(2*p.y,n)
			k=((3*p.x**2+self.a)*tmp)%n
		res=Pair()
		res.x=(k**2-p.x-q.x)%n
		res.y=(k*(p.x-res.x)-p.y)%n
		return res

	def bits(self,n) : #representation binaire de n
			while n:
				yield n & 1
				n >>= 1

	def doublePoint(self,n,P,m) :
		result=Pair()
		addend=P
		for bit in self.bits(n):
			if bit==1:
				result=self.add(result,addend,m)
			
			addend=self.add(addend,addend,m)
		return result
	

	def choixCles(self) :   		
	    	self.a=self.courbe.a
	    	self.b=self.courbe.b
	    	self.p=self.courbe.field.p
	    	self.g.x=self.courbe.g.x
	    	self.g.y=self.courbe.g.y
	    	self.privatek=random.randint(1, self.courbe.field.n) #n est l'ordre du sous groupe
	    	#print("la cle privee est : ",self.privatek)
	    	self.publick=self.doublePoint(self.privatek,self.g,self.p)
	    	#print("la cle publique :" ,self.publick)

	def calculCleSecret(n,destk):
		result=doublePoint(self.privatek,destk,self.p)	
		return result

	def mappingChaine(self,msg):
		res=''.join(format(ord(x),'07b')for x in msg)
		#print(res)
		n=50
		ch=res+""
		if len(ch)>n:
			exp=".{1,"+str(n)+"}"
			liste=re.findall(exp,ch)
		else:
			liste=re.findall('.{1,}',ch)
		#print(liste)
		for i in range(len(liste)):
			liste[i]=binaryToDecimal(int(liste[i]))
		#print(liste)
		return liste

	def chiffrement(self,msg,name):
		k=random.randint(1,self.courbe.field.n)
		point = []
		liste=self.mappingChaine(msg)
		r=random.randint(30,55)
		for i in range(len(liste)):
			for j in range(1,r) :
				pi=Pair()
				pi.x=(liste[i]*r+j)%self.p
				pi.y=((pi.x**3+self.a*pi.x+self.b)**2)%self.p
				if ec.Point(self.courbe,pi.x,pi.y).on_curve==True :
					break
			point.append(pi)
		#print(point)
		p1=self.doublePoint(k,self.g,self.p)
		p2=self.doublePoint(k,name.publick,self.p)
		crypt = []
		for i in range(len(point)):
			crypt.append(self.add(point[i],p2,self.p))

		path=os.getcwd()+"/"+str(name.name)
		filecrypt=open(path+"/msgcrypte.txt","w")
		filecrypt.write("#p1.x= #"+str(p1.x))
		filecrypt.write("#p1.y= #"+str(p1.y))
		filecrypt.write("#msgcrypte= #"+str(crypt))
		filecrypt.write("#r= #"+str(r))
		filecrypt.close()


	def dechiffrement(self):
		path=os.getcwd()+"/"+self.name
		filecrypt=open(path+"/msgcrypte.txt","r")
		liste=filecrypt.read().split("#",-1)
		p=Pair()
		p.x=int(liste[2])
		p.y=int(liste[4])
		crypt=(liste[6][:-1]).split(",",-1)
		for i in range(len(crypt)) :
			crypt[i]=crypt[i][2:][:-1]
			l=crypt[i].split(";",-1)
			pi=Pair()
			pi.x=int(l[0])
			pi.y=int(l[1])
			crypt[i]=pi
		r=int(liste[8])
		decimal = []
		decrypt = []
		val=self.doublePoint(self.privatek,p,self.p)
		val.y=(-val.y)%self.p
		for i in range(len(crypt)):
			decrypt.append(self.add(crypt[i],val,self.p))
			decimal.append(int(math.floor((decrypt[i].x%self.p)/r)))
		#print(decrypt)
		#print(decimal)
		for v in range(len(decimal)-1) :
			decimal[v]=decimalToBinary(decimal[v],50)
		decimal[len(decimal)-1]=str(bin(decimal[len(decimal)-1])[2:])
		#print(decimal)
		msgbinaire=convert(decimal)+'2'
		#print(msgbinaire)
		#*****************************************************************************
		msgclaire=""
		i=0 
		j=7
		while j<len(msgbinaire):
			msgclaire+=chr(binaryToDecimal(int(msgbinaire[i:j])))
			i=j
			j=j+7
			if j>=len(msgbinaire):
				j=len(msgbinaire)
		#****************************************************************************
		path=os.getcwd()+"/"+self.name
		filemsgdecrypt=open(path+"/msgresultant.txt","w")
		filemsgdecrypt.write(msgclaire)

	def traitement(self):
		path=os.getcwd()
		if not os.path.exists(self.name):
 			os.makedirs(self.name)
 		path=path+"/"+self.name
		filePrivate=open(path+"/privatek.key", "w")
		filePublic=open(path+"/publick.key","w")
		filePublic.write("La clé publique : ("+str(self.publick.x)+","+str(self.publick.y)+")")
		filePrivate.write("La clé privée :"+str(self.privatek))
		filePublic.close()
		filePrivate.close()


	def exchange(self,name):
		path=os.getcwd()+"/"+name
		filePublic=open(path+"/"+self.name+"publick.key","w")
		filePublic.write("La clé publique de "+self.name+" : ("+str(self.publick.x)+","+str(self.publick.y)+")")



Alice=Personne("Alice")
Alice.defintionCourbe()
Alice.choixCles()
Alice.traitement()

Bob=Personne("Bob")
Bob.defintionCourbe()
Bob.choixCles()
Bob.traitement()
Bob.exchange("Alice")

Alice.chiffrement("La cryptographie sur les courbes elliptiques (en anglais, elliptic curve cryptography ou ECC) regroupe un ensemble de techniques cryptographiques qui utilisent une ou plusieurs proprietes des courbes elliptiques, ou plus generalement d'une variete abelienne. Lusage des courbes elliptiques en cryptographie a ete suggere, de maniere independante, par Neal Koblitz et Victor Miller en 19851,2. Lutilisation de ces proprietes permet d'ameliorer les primitives cryptographiques existantes, par exemple en reduisant la taille des cles cryptographiques, ou de construire de nouvelles primitives cryptographiques qui netaient pas connues auparavant3",Bob)
Bob.dechiffrement()

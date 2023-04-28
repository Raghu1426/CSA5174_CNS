# -*- coding: utf-8 -*-
"""
Created on Fri Apr 28 13:42:13 2023

@author: Admin
"""

ct=input("Enter the cipher text : ")
pt=""
k=int(input("Enter the key:"))
print("value of k :",k)
x=len(ct)
for i in range(0,x):
    temp=ct[i]
    if(temp==" "):
        pt=pt+" "
    elif(temp.isupper()):
        pt=pt+chr((ord(temp)-k-65)%26 +65)
    else:
        pt=pt+chr((ord(temp)-k-97)%26 +97)
print("The plain text is : "+pt)

# -*- coding: utf-8 -*-
"""
Created on Fri Apr 28 12:39:52 2023

@author: Admin
"""
pt=input("Enter the plain text : ")
ct=""
k=int(input("Enter the key:"))
print("value of k :",k)
x=len(pt)
for i in range(0,x):
    temp=pt[i]
    if(temp==" "):
        ct=ct+" "
    elif(temp.isupper()):
        ct=ct+chr((ord(temp)+k-65)%26 +65)
    else:
        ct=ct+chr((ord(temp)+k-97)%26 +97)
print("The cipher text is : "+ct)
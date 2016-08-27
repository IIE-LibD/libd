# -*- coding: utf-8 -*-
"""
Created on Thu Jul 07 20:10:10 2016

@author: LMH-PC
"""

import os,sys

def get_total(currentdir):
    totallist=[]
    for dirpath, dirnames, filenames in os.walk(currentdir+os.sep+'multimodules'):
        for filename in filenames:
            fd=open(dirpath+os.sep+filename)
            for line in fd.readlines():
                line=line.strip()
                totallist.append(line)
    return totallist
if __name__=="__main__":
    #totallist=[]
    fd=open("totalmultimodules.txt",'w')
    currentdir=os.getcwd()
    print currentdir
    totallist=get_total(currentdir)
    print len(totallist)
    totalset=set()
    for lib in totallist:
        totalset.add(lib)
    print len(totalset)
    tlist=list(totalset)
    templist=tlist
    countset=set()
    for item in tlist:
        libcount=0
        libname=item[:item.find("==")]
        for name in templist:
            temp=name[:name.find("==")]
            if libname==temp:
                libcount+=1
        #print libname,libcount
        tempstr=''
        tempstr+=libname+"==>"
        tempstr+=str(libcount)
        #print tempstr
        countset.add(tempstr)
    countlist=list(countset)
    for purlib in countlist:
        fd.write(purlib)
        fd.write("\n")
    fd.close()
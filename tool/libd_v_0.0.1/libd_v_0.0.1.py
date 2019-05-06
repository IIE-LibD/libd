# -*- coding utf-8 -*-
"""
Create on Thu Aug 27, 2016
@author is lmh
"""
import shutil
import sys
import os
import re
import types
import hashlib
import time,datetime

from optparse import OptionParser

from androguard.core.androgen import Androguard
from androguard.core import androconf
from androguard.core.analysis import analysis
from androguard.core.bytecodes import dvm
from androguard.core.bytecode import method2dot, method2format
from androguard.decompiler import decompiler

#count = 1  
#dvmcodestr = ""

def valid_class_name(class_name):
    if class_name[-1] == ";":
        return class_name[1:-1]
    return class_name


def create_directory(class_name, output):
    output_name = output
    if output_name[-1] != "/":
        output_name = output_name + "/"

    pathdir = output_name + class_name
    try:
        if not os.path.exists(pathdir):
            os.makedirs(pathdir)
    except OSError:
        # FIXME
        pass

#Decompile APK
#return --> list of [[vm, vms]]
def decompile(apkname, output):
    print "Dump information %s in %s" % (apkname, output)
    apk_vm_serial = []
    a = Androguard([apkname])
    decompiler_type = None
    
    if not os.path.exists(output):
        print "Create directory %s" % output
        os.makedirs(output)
    else:
        print "Clean directory %s" % output
        androconf.rrmdir(output)
        os.makedirs(output)
    
    output_dir = output
    if output_dir[-1] != "/":
        output_name = output_dir + "/"
    print "Output dir: %s" % output_dir
    
    for vm in a.get_vms():
        vm_list = []    #vm_list = [vm, vmx]
        print "Analysis ...",
        sys.stdout.flush()
        vmx = analysis.VMAnalysis(vm)
        vm_list.append(vm)
        vm_list.append(vmx)
        print "End"
        
        print "Decompilation ...",
        sys.stdout.flush()
    
        if not decompiler_type:
            vm.set_decompiler(decompiler.DecompilerDAD(vm, vmx))
        elif decompiler_type == "dex2jad":
            vm.set_decompiler(decompiler.DecompilerDex2Jad(vm,
                                                           androconf.CONF["PATH_DEX2JAR"],
                                                           androconf.CONF["BIN_DEX2JAR"],
                                                           androconf.CONF["PATH_JAD"],
                                                           androconf.CONF["BIN_JAD"],
                                                           androconf.CONF["TMP_DIRECTORY"]))
        elif decompiler_type == "dex2winejad":
            vm.set_decompiler(decompiler.DecompilerDex2WineJad(vm,
                                                               androconf.CONF["PATH_DEX2JAR"],
                                                               androconf.CONF["BIN_DEX2JAR"],
                                                               androconf.CONF["PATH_JAD"],
                                                               androconf.CONF["BIN_WINEJAD"],
                                                               androconf.CONF["TMP_DIRECTORY"]))
        elif decompiler_type == "ded":
            vm.set_decompiler(decompiler.DecompilerDed(vm,
                                                       androconf.CONF["PATH_DED"],
                                                       androconf.CONF["BIN_DED"],
                                                       androconf.CONF["TMP_DIRECTORY"]))
        elif decompiler_type == "dex2fernflower":
            vm.set_decompiler(decompiler.DecompilerDex2Fernflower(vm,
                                                                  androconf.CONF["PATH_DEX2JAR"],
                                                                  androconf.CONF["BIN_DEX2JAR"],
                                                                  androconf.CONF["PATH_FERNFLOWER"],
                                                                  androconf.CONF["BIN_FERNFLOWER"],
                                                                  androconf.CONF["OPTIONS_FERNFLOWER"],
                                                                  androconf.CONF["TMP_DIRECTORY"]))
        else:
            raise("invalid decompiler !")
        apk_vm_serial.append(vm_list)
        print "End"
    return apk_vm_serial

#return --> method_dict = {method_name: [set(invoke_info), CFG_Hash]} class_list = [[clasname, classcontent], ...]
def method_info_index(apk_vm_serial, output):
    methods_filter_expr = None
    
    method_dict = {}    #method_dict = {method_name: method_info[[invoke_info], CFG_Hash]}
    method_name_list = []
    dump_classes = []   
    classes_list = [] 
    
    #get vm_list from apk_vm_serial
    for vm_list in apk_vm_serial:
        vm = vm_list[0]
        vmx = vm_list[1]
        for method in vm.get_methods():
            method_info = []    #method_info = [set([invoke_info]), CFG_Hash]
            invoke_info = []
            method_opcode_str = ""
            filename_class = valid_class_name(method.get_class_name())
            if filename_class.find("android/support/v4") != -1:
                continue
            create_directory(filename_class, output)
    
    #        print "Dump %s %s %s ..." % (method.get_class_name(),
    #                                     method.get_name(),
    #                                     method.get_descriptor()),
    
            output_dir = output
            if output_dir[-1] != "/":
                output_dir = output_dir + "/"            
            filename_class = output_dir + filename_class
            if filename_class[-1] != "/":
                filename_class = filename_class + "/"
    
            descriptor = method.get_descriptor()
            descriptor = descriptor.replace(";", "")
            descriptor = descriptor.replace(" ", "")
            descriptor = descriptor.replace("(", "-")
            descriptor = descriptor.replace(")", "-")
            descriptor = descriptor.replace("/", "_")
            
            filename = filename_class + method.get_name() + descriptor
            if len(method.get_name() + descriptor) > 250:
                all_identical_name_methods = vm.get_methods_descriptor(method.get_class_name(), method.get_name())
                pos = 0
                for i in all_identical_name_methods:
                    if i.get_descriptor() == method.get_descriptor():
                        break
                    pos += 1
            
                filename = filename_class + method.get_name() + "_%d" % pos
               
            if method.get_class_name() not in dump_classes:
                #class's name-content pair --> [name, content]  
                cls_nc_pair = []

                #print "source codes ...",
                current_class = vm.get_class(method.get_class_name())
                current_filename_clas = valid_class_name(current_class.get_name())
                # create_directory(filename_class, output)
    
#                current_filename_class = output_dir + current_filename_clas + ".java"
#                with open(current_filename_class, "w") as fd:
#                    fd.write(current_class.get_source())
                dump_classes.append(method.get_class_name())
                #fileclassname = output_dir+current_filename_clas
                fileclassname = "L" + current_filename_clas
                cls_nc_pair.append(fileclassname)
                #cls_nc_pair.append(current_class.get_source())
                classes_list.append(cls_nc_pair)
            
            bytecode_buff = dvm.get_bytecodes_method(vm, vmx, method)
            line_s = bytecode_buff.split("\n")

            #two procedures for each line
            for line in line_s:    

                if line.startswith("\t"):
                
                    #1st: find 'invoke' information
                    if line.find("invoke") != -1:
                        #invoke relation Lcom/xxx/yyy;->Lcom/sss/uuu;
                        #invokelist = [Lcom/xxx/yyy, "->", Lcom/sss/uuu]
                        invoke_rel = ""
                        tempstr1 = ""
                        tempstr2 = ""
                        ir = line[line.find("L"):]
                        #print "line:", line
                        #print "ir:", ir
                        if ir.find("->") != -1:
                            cls_rels = ir.split("->")

                            tempstr1 = cls_rels[0][cls_rels[0].find("L"):cls_rels[0].find(";")]

                            if cls_rels[1].find("/") != -1 and cls_rels[1][:cls_rels[1].find("/")].rfind("L") != -1:
                                pos = cls_rels[1][:cls_rels[1].find("/")].rfind("L")
                                tempstr2 = cls_rels[1][pos:cls_rels[1].find(";")]
    
                            if not (tempstr1.startswith("Ljava") or tempstr1.startswith("Landroid")
                            or tempstr2.startswith("Ljava") or tempstr2.startswith("Landroid") or 
                            tempstr1 == tempstr2):
                                if len(tempstr2) != 0:
                                    invoke_rel += tempstr1
                                    invoke_rel += "->"
                                    invoke_rel += tempstr2
                            
                            if invoke_rel != "":
                                invoke_info.append(invoke_rel)
                        
                if line.startswith("\t"):
                    #2nd: computing the HASH Value of mthod
                    #line = line.strip()
                    line = line.strip()
                    tttt = line.find(")")
                    templine = line[tttt+2:]
                    #if the method contain opcode like:
                    #    goto target, goto/16 target, goto/32 target
                    #    if-xx xx,xx,target 
                    if templine.startswith("if") or templine.startswith("goto"):
                        if templine.rfind(" ") != -1:
                            spcpos = templine.find(" ")
                            rspcpos = templine.rfind(" ")
                            dvmopcode = templine[:spcpos]+templine[rspcpos:]
                    elif templine.find("switch") != -1:
                        if templine.rfind(", ") != -1:
                            spcpos = templine.find(" ")
                            rspcpos = templine.rfind(", ")
                            dvmopcode = templine[:spcpos]+templine[rspcpos+2:]
                    else:
                        rightposition = templine.find(" ")
                        #print templine[:rightposition]
                        dvmopcode = templine[:rightposition]
                    #print dvmopcode
                    method_opcode_str += dvmopcode
            # =============================================================================================
            # the calculation code of the method hash does not fit the discription in our paper.
            # It is my fault, i mistakenly mixed our alpha version code and final version together
            # I will search our server and fix it as soon as possible
            # --Thanks to Arash Vahidi--
            # ==============================================================================================
    
            #compute the Hash value of each method
            methodmd5 = hashlib.md5()
            methodmd5.update(method_opcode_str)
            method_md5_index =methodmd5.hexdigest()

            method_name_list.append(filename)
            set_invoke_info = set(invoke_info)
            method_info.append(set_invoke_info)
            method_info.append(method_md5_index)
            
            method_dict[filename] = method_info
            
    return method_dict, classes_list       

    
#compute the HASH Value of the classes in classes_list
#using the classes_list, method_dict, and method_name_list
def class_info_index(classes_list, method_dict):
    classes_info_dict = {}
    classcount = 0
    method_list = method_dict.keys()
    #print "method_list", method_list
    for cls_nc_pair in classes_list:
        class_info = []
        class_cfg = ""
        method_hash_list = []
        classname = cls_nc_pair[0]
        class_invoke_set = set()
        for method in method_list:
            method_info = method_dict[method]
            #print method.count(classname)
            if method.count(classname[1:]) == 1:
                method_hash = method_info[1]
#                print method_hash
                method_hash_list.append(method_hash)
                
                method_invoke_set = method_info[0]
                class_invoke_set.update(method_invoke_set)
                
        method_hash_list.sort()
        
        for method_hash in method_hash_list:
            class_cfg += method_hash
        
        class_md5 = hashlib.md5()
        class_md5.update(class_cfg)
        class_cfg_index = class_md5.hexdigest()
        
        class_info.append(class_cfg_index)
        class_info.append(class_invoke_set)
        #print class_cfg_index
        #clsname = classname + ".smali"
        classes_info_dict[classname] = class_info
        
    return classes_info_dict

#input ---> method_dict
#output --> set(classes_invoke_info)
def classes_invoke_info(method_dict):
    classes_invoke_info = set()
    method_list = method_dict.keys()    
    for method in method_list:
        method_info = method_dict[method]
        method_invoke_info = method_info[0]
        
        #append invoke info to class_invoke_info set
        classes_invoke_info.update(method_invoke_info)
    return classes_invoke_info

#filter invoke relationship
#input ---> classes_invoke_info, filter level(2 or 3)
#output --> dict{dir_name: set[Same second dir invoke info]}, set[others]
def filter_invoke_rel(classes_invoke_info, filter_level):
    #the invoke relationship dict under the same filter_level:
    #dict_name:list[sub dir classes invoke info]    
    filter_level_dict = {}
    filter_level_set = set()
    
    #save same dir invoke relationship in pass_filter
    #save others in pass_filter
    pass_filter = set()
    unpass_filter = set()
    if filter_level != 2 and filter_level != 3:
        print "Error filter_level param:", filter_level
        print "Please set the filter_level as 2 or 3!"
        return 
    classes_invoke_list = list(classes_invoke_info)
    #print classes_invoke_list
    #class_invoke is string "Lcom/sss/...->L/com/sss/..."
    for class_invoke in classes_invoke_list:
        cmp_list = class_invoke.split("->")
        if len(cmp_list) == 2:
            dir_1 = level_filter(cmp_list[0], filter_level)
            dir_2 = level_filter(cmp_list[1], filter_level)
    
            if dir_1 == dir_2:
                filter_level_set.add(dir_1)
                pass_filter.add(class_invoke)
            else:
                unpass_filter.add(class_invoke)
    
    filter_list = list(filter_level_set)
    pass_invoke_list = list(pass_filter)
    
    for level_name in filter_list:
        sub_invoke_list = []
        for pass_invoke in pass_invoke_list:
            if pass_invoke.find(level_name) != -1:
                sub_invoke_list.append(pass_invoke)
        filter_level_dict[level_name] = sub_invoke_list
    
    return filter_level_dict, unpass_filter

#filter the dir the class belongs to
#input ---> abstract class name, filter level(2 or 3)
#output --> the dir name the class belongs on the special level 
def level_filter(cls_abs_name, level):
    tmp = cls_abs_name
    count = 0
    for i in range(level):
        coun = tmp.find("/")
        #print coun
        count += coun
        count += 1
        #print count
        tmp = tmp[coun+1:]
    return cls_abs_name[:count]

#get 3rd dirs invoke input output degree
#input ---> dict{filter_lever(2)_dict}
#output --> list of dict cantain output, input sets
def dir_invoke_info(filter_level_dict, level):
    third_io_list = []
    for sec_dir in filter_level_dict.keys():

        third_filter_set = set(filter_level_dict[sec_dir])
        unused_dict, diff_dir_inv = filter_invoke_rel(third_filter_set, level)

        diff_inv_list = list(diff_dir_inv)

        test_list=[]
        #filter the classes under secdir
        for diff_inv in diff_inv_list:
            inv_info_list = diff_inv.split("->")
            if inv_info_list[0].count("/") >= level and inv_info_list[1].count("/") >= level:
                test_list.append(diff_inv)

#        print "diff_inv_list:"
#        print test_list
        #dict{dirname: [set(ouput,) set(input)}
        third_io_info = {}
        third_io_dir = []
        #list[output, input]
        io_info = []
        for diff_inv in test_list:
            inv_info_list = diff_inv.split("->")
            pre_dir = level_filter(inv_info_list[0], level)
            tail_dir = level_filter(inv_info_list[1], level)
            third_io_info.setdefault(pre_dir, [set(),set()])
            third_io_info.setdefault(tail_dir, [set(),set()])            
        #print "third_info_:", third_io_info
        for diff_inv in test_list:
            inv_info_list = diff_inv.split("->")
            pre_dir = level_filter(inv_info_list[0], level)
            tail_dir = level_filter(inv_info_list[1], level)
            third_io_info[pre_dir][0].add(tail_dir)
            third_io_info[tail_dir][1].add(pre_dir)
        third_io_list.append(third_io_info)
    return third_io_list

def delete_file_folder(src):
    '''delete files and folders'''
    if os.path.isfile(src):
        try:
            os.remove(src)
        except:
            pass
    elif os.path.isdir(src):
        for item in os.listdir(src):
            itemsrc=os.path.join(src,item)
            delete_file_folder(itemsrc)
        try:
            os.rmdir(src)
        except:
            pass

#extract function library 
#input ---> APK abstract path
def funclibext(apkname,outputpath):
    de_start=datetime.datetime.now()
    apk_vm_serial = decompile(apkname, outputpath)
    de_end=datetime.datetime.now()
    print '=================='
    print 'Decompile:', de_end-de_start
    print '=================='

    mi_start=datetime.datetime.now()
    method_dict, classes_list = method_info_index(apk_vm_serial, outputpath)
    mi_end=datetime.datetime.now()
    print '==================='
    print "method_info_index Time:", mi_end-mi_start
    print '==================='

    total_lib_inv = []    #Second_dir level['secdir lib', ['single third dir lib'],[['multi third dir ilb'],...]]
    first_lib_set = set()
    third_dir_set = set()
    sec_dir_set = set()
    fourth_dir_set = set()
    cls_list = []
    for classnamelist in classes_list:
        cls_list.append(classnamelist[0])
        if classnamelist[0].count("/") == 1:
            first_lib_set.add(level_filter(classnamelist[0], 1))
        sec = level_filter(classnamelist[0], 2)
        if sec.count("/") == 2:
            sec_dir_set.add(sec)
        if classnamelist[0].count("/") >= 3:
            third_dir_set.add(level_filter(classnamelist[0], 3))
#        if classnamelist[0].find("com/umeng/") != -1:
#            print classnamelist[0]
#    return
#==============================================================================
# add first level dir lib into the total_lib_inv list
#==============================================================================
    if len(first_lib_set) != 0:    
        for first_lib in list(first_lib_set):
            total_lib_inv.append(first_lib)

    incon = 0
    classes_info = class_info_index(classes_list, method_dict)

#    for classname in classes_info:
#        incon += len(classes_info[classname][1])
#    print "incon:", incon
#    
    cls_inv = classes_invoke_info(method_dict)
    cls_inv_list = list(cls_inv)
#    print "cls_len:", len(cls_inv)
#    clscon = 0

#    for cls in cls_inv_list:
#        if cls.find("->") != -1:
#            clscon += 1
#    print "cls_inv -> count:", clscon
    third_dir_list = list(third_dir_set)
#    print "third_dir_list:", third_dir_list
    
#    for cls in cls_list:

#    for third_dir in third_dir_list:
#        sec_dir_set.add(level_filter(third_dir, 2))
    #print sec_dir_set
#    print third_dir_set
    pre_filter_2_dict, unpass_filter = filter_invoke_rel(cls_inv, 2)
   
#    print pre_filter_2_dict.keys()
    print len(pre_filter_2_dict)
    #sec_dir_list = pre_filter_2_dict.keys()
    sec_dir_list = list(sec_dir_set)
    #filter the sec dir that directly contain classes in it
    sec_lib_set = set() 
    
#    for cls_name in classes_info.keys():
#        if outputpath[-1] != "/":
#            outputpath = outputpath + "/"
#        cls_name = cls_name[len(outputpath):]
#        cls_list.append(cls_name)
    #print "cls_list", cls_list
    for sec_dir in sec_dir_list:
        for cls in cls_list:
            if cls.find(sec_dir[1:]) != -1:
                if cls.count("/") == 2:
                    sec_lib_set.add(sec_dir)
    #sec dir lib list 
#    print "sec_lib_set", sec_lib_set
    sec_lib_list = list(sec_lib_set)
    for sec_lib in sec_lib_list:
        total_lib_inv.append(sec_lib)
        
    filter_2_dict = {}
    for filter_lib in pre_filter_2_dict.keys():
        if filter_lib not in sec_lib_set:
            filter_2_dict[filter_lib] = pre_filter_2_dict[filter_lib]
#    print "filter_2_dict:", filter_2_dict.keys()
        
    third_inv_info = dir_invoke_info(filter_2_dict,3)
#    print "third_inv_info", third_inv_info
    
    tmp_sec_third_map = {}
    for sec_name in sec_dir_list:
        temp = []
        for third_name in third_dir_list:
            if third_name.find(sec_name) != -1:
                temp.append(third_name)
        tmp_sec_third_map[sec_name] = temp
#    print "sec_third", tmp_sec_third_map
    
    sec_third_map={}
    #filter the sec_dir_lib and those sec_dirs that do not exists in 
    for sec_name in tmp_sec_third_map:
        if sec_name not in sec_lib_set:
            if len(tmp_sec_third_map[sec_name]) != 0:
                sec_third_map[sec_name] = tmp_sec_third_map[sec_name]
#    print "modify:", sec_third_map
    
    #filter the third level dirs that do not invoke each other---filter from third_inv_info
    #insert them into total_lib_inv
    #get all no invoke third level dir invoke
    sec_third_unempty_map = {}
    for third_inv in third_inv_info:
        if len(third_inv) != 0:
            empty_third_list = []
            third_inv_list = third_inv.keys()
#            print "third_inv_list", third_inv_list
            sec_map = level_filter(third_inv_list[0],2)
#            print sec_map
            if sec_map in sec_third_map.keys():
                total_third_list = sec_third_map[sec_map]
                for third_dir in total_third_list:
                    if third_dir not in third_inv_list:
                        empty_third_list.append(third_dir)
                sec_third_unempty_map[sec_map] = empty_third_list
                if len(empty_third_list) != 0:
                    total_lib_inv.append(empty_third_list)
#    print "sec_third_unempty_map:", sec_third_unempty_map
 
    #get rest third_dirs
    for sec_name in sec_third_map:
        if sec_name not in sec_third_unempty_map:
            total_lib_inv.append(sec_third_map[sec_name])

    unempty_inv_list = []
    for third_inv in third_inv_info:
        output_list = []
        input_list = []
        loop_inv_list = []
        for key in third_inv.keys():
            output_list.append(third_inv[key][0])
            input_list.append(third_inv[key][1])
        #print "output_list:", output_list
        if len(third_inv) != 0:
            #3 kinds of different handle scheme:
            #1) invoke graph has both start and end points (the vertexes which output degree is 0, and input degree is 0)
            #2) invoke graph has only the start points
            #3) invoke graph has no start and end points
            if (set([]) in output_list) and (set([]) in input_list):
                #kinds 1)
                #find the dir input set() == None
                #lib_inv = [io_rel, io_rel, ...]
                lib_inv_one = []
                #print "third_inv", third_inv
                third_dirs = third_inv.keys()
                in_none = []
                out_none = []
                for key in third_inv.keys():
                    #print third_inv[key][0]
                    if len(third_inv[key][0]) != 0 and \
                        len(third_inv[key][1]) == 0:
                        in_none.append(key)
                    elif len(third_inv[key][1]) != 0 and\
                          len(third_inv[key][0]) == 0:
                        out_none.append(key)
                #print "in_none:", in_none
                #print "out_none:", out_none
                #print "third_inv:", third_inv

                inv_libs = []
                for start in in_none:
                    if len(out_none) != 0:
                        for end in out_none:
                            lib_list = []
                            merge_lib(start, end, third_inv, lib_list)
                            inv_libs.append(lib_list)   
                #print "inv_libs:", inv_libs

                total_lib_inv.append(inv_libs)
                unempty_inv_list.append(inv_libs)
                
                #find the other loop libs in the same sec_dir
                tmplist = []
                for sublist in inv_libs:
                    for libname in sublist:
                        tmplist.append(libname)
                #print "tmp", tmplist
                loop_lib_list = []
                sec_dir = level_filter(tmplist[0], 2)
                if sec_dir in sec_third_map.keys():
                    for third_dir in sec_third_map[sec_dir]:
                        if third_dir not in tmplist and third_dir not in sec_third_unempty_map[sec_dir]:
                            loop_lib_list.append(third_dir)
#insert all these loop lib into total_lib_inv as single libs   
                print "------------------------------------"
                while (len(loop_lib_list) > 0):
                    loop_lib_list, pre_inser_list = loop_lib(loop_lib_list, third_inv)
                    if len(pre_inser_list) !=0:
                        inser_list = []
                        inser_list.append(pre_inser_list)
                        total_lib_inv.append(inser_list)
                    
            else:
                #the rest libs contain solo third_dir
                third_inv_libs = []
                sec_dir_name = level_filter(third_inv.keys()[0],2)

                if (sec_dir_name in sec_third_unempty_map.keys()) and\
                  (len(sec_third_unempty_map[sec_dir_name]) != 0):
                      third_inv_libs.append(third_inv.keys())
                      total_lib_inv.append(third_inv_libs)

                else:
                    sec_lib_set_two = set()
                    loop = third_inv.keys()
                    #print "loop", loop
                    if len(loop) != 0:
                        for each_lib in loop:
                            #print "each_lib", each_lib
                            sec_lib_set_two.add(level_filter(each_lib, 2))
                        #print "sec_lib_set", sec_lib_set_two
                    if len(sec_lib_set_two) != 0:
                        sec_lib_list_two = list(sec_lib_set_two)
                        #print "sec_lib_list_two:", sec_lib_list_two
                        for each_lib in sec_lib_list_two:
                            unempty_inv_list.append(each_lib)
                            total_lib_inv.append(each_lib)
    unempty_secdir_set = set()
#    print "unempty_inv_list", unempty_inv_list

#    print "total lib 222--------------------", len(total_lib_inv)
#    print "total lib 222", total_lib_inv
#    total_lib_inv = list(set(total_lib_inv))
#    print "total lib 333:", len(total_lib_inv)

    lib_name_list = []
    lib_content_list=[]
    for pre_lib in total_lib_inv:
        if type(pre_lib) == str:
            lib_content_list.append(pre_lib)
            lib_name_list.append(pre_lib)
        elif type(pre_lib) == list:
            for sub_lib in pre_lib:
                if type(sub_lib) == str:
                    lib_name_list.append(sub_lib)
                elif type(sub_lib) == list:
                    lib_name_list.append(sub_lib[0])
                lib_content_list.append(sub_lib)

    lib_dicts = {}
    for i in range(len(lib_name_list)):
        lib_name = lib_name_list[i]
        lib_content = lib_content_list[i]
        #print "lib_content", lib_content
        lib_info =[]
        if type(lib_content) == str:
            if len(lib_content) > 1:
                lib_index = dir_index(lib_content, classes_info)
                lib_info.append(lib_content)
                lib_info.append(lib_index)
                lib_dicts.setdefault(lib_name, lib_info)
        elif type(lib_content) == list:
            #=================================================================
            #filter the same components in lib_content
            #=================================================================
            lib_set = set(lib_content)
            lib_content = list(lib_set)
            content_index_list = []
            for content in lib_content:
                #print "type of content:", type(content)
                if len(content) > 1:
                    content_index_list.append(dir_index(content, classes_info))
            content_index_list.sort()
            print "content_list_len", len(content_index_list)
            content_index = ""
            for index in content_index_list:
                content_index += index
            lib_md5 = hashlib.md5()
            lib_md5.update(content_index)
            lib_index = lib_md5.hexdigest()
            #lib_info.append(content)
            lib_info.append(lib_content)
            lib_info.append(lib_index)
            lib_dicts.setdefault(lib_name, lib_info)
    #return total_lib_inv
    return lib_dicts, classes_info
    
#merge lib ----- get all paths from the in_none to the out_none
#input ---> start(in in_none), end(in out_none), inv_dict, inv_list=[]
#output --> paths(inv_list_1, inv_list_2, ...)
#source: http://devres.zoomquiet.io/data/20071011232111/index.html
def merge_lib(start, end, inv_dict, inv_list = []):
    inv_list.append(start)
    if start == end:
        return inv_list
    if not inv_dict.has_key(start):
        return []
    paths = []
    for node in list(inv_dict[start][0]):
        if node not in inv_list:
            newpaths = merge_lib(node, end, inv_dict, inv_list)
            for newpath in newpaths:
                paths.append(newpath)
    #return paths
    lib_set = set()
    for path in paths:
        for node in path:
            lib_set.add(node)
    return list(lib_set)

#loop lib
def loop_lib(loop_lib_list, third_inv):
    if len(loop_lib_list) != 0:
        #build list[set(third_inv.key, output, input), ...]
        next_loop_set = set()
        temp_set = set()
        loop_set_list = []
        for loop_lib in loop_lib_list:
            loop_set = set()
            if loop_lib in third_inv.keys():
                loop_set.add(loop_lib)
                loop_set.update(third_inv[loop_lib][0])
                loop_set.update(third_inv[loop_lib][1])
                loop_set_list.append(loop_set)
        #find the loop lib
        tempset = loop_set_list[0]
        for j in range(len(loop_lib_list)):
            if j != 0:
                for third_dir in list(loop_set):
                    if third_dir in tempset:
                        tempset.update(loop_set)
                        #temp_set.add(loop_lib_list[j])
                        break
        return list(set(loop_lib_list).difference(tempset)), list(tempset)

#dir_index
def dir_index(dir_path, classes_info):
    classesName =classes_info.keys()

    classes_index_list = []
    for classname in classesName:
        if classname.find(dir_path[1:]) != -1:
            classes_index_list.append(classes_info[classname][0])
    classes_index_list.sort()
    #print "classes_index_list:", len(classes_index_list)
    cls_index = ""
    for classes_index in classes_index_list:
        cls_index += classes_index
    #print "cls_index", cls_index
    dir_md5 = hashlib.md5()
    dir_md5.update(cls_index)
    dir_index = dir_md5.hexdigest()
    return dir_index
#main()
def main(apkname, outputpath, lib_info):
    #apkname = "/home/lmh/Desktop/Download/c21e41e30ad2221dabea0ee533141276.apk"
    #outputpath = "/home/lmh/Desktop/output/1c4b/"
    #total_lib_list = [lib_list in secdir_1, lib_list in secdir_2, ...]
    time_start=datetime.datetime.now()
    total_lib_dicts, clazz_info = funclibext(apkname, outputpath)
    time_end=datetime.datetime.now()
    print '==================='
    print "Time:", time_end-time_start
    print '==================='
    #print total_lib_dicts
    #print "len of clazz_info", len(clazz_info)
    #fd = open(apkname + ".txt", 'w')
    fd=open(lib_info, 'w')
    for item in total_lib_dicts:
        print item
        fd.write(item[1:-1]+': {')
        if type(total_lib_dicts[item][0])==list:
            fd.write('[')
            for ii in total_lib_dicts[item][0]:
                #fd.write('[')
                fd.write(ii[1:-1])
                fd.write(', ')
            fd.write('], ')
        else:
            fd.write(total_lib_dicts[item][0][1:-1]+', ')
        fd.write(str(total_lib_dicts[item][1]))
        fd.write('}\n')
    #fd.write(str(total_lib_dicts))
    fd.close()    
    
#    rootpath = "/home/lmh/MyDev/funclibtest/ceshi/ceshijiAPK/"
#
#    print rootpath
#    apknamelist = []
#    for dirpath, dirnames, filenames in os.walk(rootpath):
#        apknamelist = filenames
#    for apkname in apknamelist:
#        apkname_1 = rootpath + apkname
#        outputpath = "/home/lmh/MyDev/funclib/testresult/"+apkname+'/'
#        g_path = "/home/lmh/MyDev/funclib/testresult/"
#        total_lib_dicts = funclibext(apkname_1, outputpath)
#        fd = open(g_path+apkname + ".txt", 'w')
#        fd.write(str(total_lib_dicts))
#        fd.close()

if __name__=="__main__":
    if len(sys.argv)!=4:
        print "Please Enter 3 Parameters following the order: apk decompiledpath lib_info"
    else:
        apkname=sys.argv[1]
        outputpath=sys.argv[2]
        lib_info=sys.argv[3]
        main(apkname,outputpath,lib_info)

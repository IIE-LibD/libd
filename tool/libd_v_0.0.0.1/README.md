README
------
##LibD Version 0.0.0.1
This version is a raw prototype of the LibD of the system level.
It provides the basic analysis functionality to get the potential library instances and their correspoding features.
After comparing with the libreary lists in /liblist dir, the potential libraries would be picked out.
###Pre-install
Operating system:
    Linux (We test it on Ubuntu 14.04)

Running environment:
    Python 2.7

LibD depends on two decompiling tools:   
    Apktool  
    Androguard  

###Use LibD:
In the terminal, use the command line below: 
```bash
$ python libd_v_xxx.py _path/to/APK/file_ _path/to/decompilation/output/dir_ _library/instances/list/file_
```
(The First parameter is the APK file that wanted to be analyzed, the second parameter is pre-created decompiling folder, the third parameter is the name of the output file that would contain libraries instances in the APK, which could be named by the user in the command line.)  
or modify the script to fit your purposes.

The first input parameter is the path to your apk file.  

The second input parameter is the directory which is prepared for the decompiled files by decompiler such as Apktool and Androgaurd.  

The third parameter is the analysis result of LibD prototype, which contains the instances and their corresponding features.

After comparing the instance names and features in the /liblist dir with different thresholds, the libraries would be filtered out..
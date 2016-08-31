README
------
###LibD Version 0.0.0.1
This system is stand-alone version of LibD. As full version of LibD is running on Openstack platform with concurrency scheduler and DataBase(MySQL) manager, we eliminate these modules for a stand-alone version. 
For a given Android Application, this version computes the potential library instances and their corresponding features as the output. You can pick out potential libraries by manually comparing LibD's output with library lists in /liblist dir.

###Pre-install
Operating system:
    Linux (We recommend you test LibD on Ubuntu 14.04)

General requirement:
    (1) Python 2.7  
    (2) OpenJDK 1.7.0 or later  
    (2) Apktool. http://ibotpeaches.github.io/Apktool/  
    (3) Androguard. https://github.com/androguard/androguard  

###Use LibD:
In the terminal, use the command line below:  

```bash
$ python libd_v_xxx.py _path/to/APK/file_ _path/to/decompilation/output/dir_ _library/instances/list/file_
```

(1)The first parameter is the path to your targeted apk file as the input.  
(2)The second parameter is a directory which contains the decompiled files by Apktool and Androgaurd.   
(3)The third parameter is a user-defined file which includes all potential library instances and their corresponding features, as the analysis result of LibD.   
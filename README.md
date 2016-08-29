README
------
# LibD
This Project has the following contributions:  
First, it provides a novel Android third-party libraries detection tool, LibD.  
Second, it contains a library list that we have found in our research  
Third, it contains the experimental results in our evaluation.   

#### The structure of this project is as following:  
1. Folder "groundthuth" contains the libraries that are manually extracted from the 1,000 sample apps. It also contains the comparison between "groundtruth" and LibD and comparison between "groundtruth" and LibRadar.  

2. Folder "liblist" contains the libraries list of different thresholds which variant from 10 to 50. In the sub-folder of "manuallyappraoch", we list the 72 libraries in the whitelist of Chen's research in "Achieving Accuracy and Scalability Simultaneously in Detecting Application Clones on Android Markets".   

3. Folder "multi-package_libs_instances" shows the multi-package library instances evaluated in section IV-F.  

4. Folder "tool" provides a locally runnable python script. It is an abbreviated version of our Libraries analysis system, which provides library instances with their names and features.  
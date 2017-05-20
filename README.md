#############################################
#####									#####	
#####     PROJECT - MULTI USER BLOG     #####
#####                                   #####
#############################################

1.0 MULTI-USER BLOG
- A simple version of multi blog with basic features. 
- Login with your username and password if you already a registered user.
- Please register if you are a new user.
- Able to view all other users post in this main page.

2.0 INSTALLATION
- Please download the following software and install on your computer.
- GIT, Python 2.7, Google Cloud Engine and Google Cloud SDK.
Refer to below web site for more information:
2.1) https://cloud.google.com/appengine/docs/standard/python/quickstart
2.2) https://docs.python.org/2/
2.3) https://git-scm.com/documentation
2.4) https://cloud.google.com/sdk/docs/

3.0 GET STARTED
- Clone your folders with all the necessary files into GIT HUB repository.
- To run the apps at your computer. 
- Open command terminal in the folder with all the files and run "dev_appserver.py app.yaml". 
- Browse to http://http://localhost:8080.

4.0 HOW TO USE THIS BLOG PAGE.
- Upon login, you will be greet by a welcome message.
- You can write and submit a new post with a subject and blog content.
- The information of the user, subject and contents will be display in this blog.
- All the posted items will be display and stored in database.
- The previous blogs were sorted by latest created date first for the first 20posts.
- Upon login, you are able to edit and delete your own post ONLY.
- Once deleted post, you will be promt error "This post does not exist" if you edit/delete the same posted-id.

5.0 TESTING THIS BLOG PAGE
- Please follow the link at http://myblog-167810.appspot.com/ to test a live version.

Additional information.
- To experience ROT13, please go to path http://myblog-167810.appspot.com/rot13
Using ROT-13 (rotate by 13 alphabets), is a simple cipher for letter substituition by replacing current letter with 13 letters after it.
Example,a --> n, A --> N, z --> m, Z --> M 
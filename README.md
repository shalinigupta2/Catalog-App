# Project Title
Item Catalog App Udacity Full Stack Nanodegree

# Description
Item Catalog App is a dynamic RESTful web application developed using the Python framework Flask along with third-party OAuth authentication. This application deals with a SQLite database which has Category, User and Category Item tables. It is styled using Bootstrap.

This application provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.

# Skills Used
```bash
*   Python
*   HTML
*   CSS
*   Bootstrap
*   Flask
*   SQLAchemy
*   Oauth2
*   Google Login
*   Facebook Login
```
# Softwares used
To complete this project, you'll require the following softwares:
```bash
Python 3
A text editor, like Sublime or Atom or Visual Studio Code or PyCharm
Vagrant
Virtual Box 
A terminal application like Bash
```
# Files used
Files This project contains 3 python file setup_database.py - to create the database catalogsAndItems.py - to populate the database itemCatalogProject.py - Main python code

Folders This project contains 2 folders static - contains the style sheets templates - HTML templates of all the files

# Executing Project
Requirements To run this final project :
```
1. Install Vagrant and VirtualBox
2. Clone the Vagrantfile from the Udacity Repo
3. Clone this repo into the catlog/ directory found in the Vagrant directory
4. Run vagrant up to run the virtual machine, then vagrant ssh to login to the VM
5. Navigate to the /catalog directory inside the vagrant environment
6. Run setup_database.py to create the database
7. Run catalogsAndItems.py to populate the database
8. Run application.py and navigate to localhost:5000 in your browser
```
# JSON Endpoints
```
1.  Catalog JSON: /catalog/catalog.json - Returns JSON of all items in catalog.
2.  Categories JSON: /catalog/<int:category_id>/JSON - Returns JSON of all categories in catalog
```
# Credits
Udacity Full Stack Web Developer Nano Degree : https://www.udacity.com/course/full-stack-web-developer-nanodegree--nd004

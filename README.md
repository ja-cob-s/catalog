## Item Catalog
Project for the Udacity Full Stack Web Development Nanodegree.

### Introduction
This project is a RESTful web application which accesses a SQL database that populates a catalog of video games and their respective genres. Users can login with either Google or Facebook. Authorized users may create perform CRUD (Create, Read, Update, Delete) operations on categories and items. Technologies used include OAuth2.0, Flask, Jinja, Bootstrap, and SQLAlchemy. The SQLite database has the following tables:
* The **User** table contains the list of authorized users.
* The **Category** table lists each category and its authorized user.
* The **Item** table lists each item with its own category and authorized user.

### Update
Instead of following the instructions below to run the web application on your localhost, you can now simply view a live version at https://shybull.net

### Requirements
* [Python 3](https://www.python.org/)
* [Vagrant](https://www.vagrantup.com/)
* [VirtualBox](https://www.virtualbox.org/wiki/Downloads)

### Getting Started
* Clone the [Udacity fullstack-nanodegree-vm repository](https://github.com/udacity/fullstack-nanodegree-vm).
* Find the `catalog` directory. Place the contents of this repository in that directory.
* Start the virtual machine: Open a console in the directory where vagrant is installed. From the console, use `vagrant up` and then login with `vagrant ssh`
* Change to the catalog directory: `cd /vagrant/catalog`
* Run the program: Use the command `python application.py`
* Open the web application in your favorite browser: [http://localhost:5000/](http://localhost:5000/)
* You may login with either Google or Facebook
 
### JSON Endpoints
The following endpoints are available:
* Catalog: `/catalog/JSON` (Displays the categories in the catalog)
* Category: `/catalog/<int:category_id>/items/JSON` (Displays all items in a category)
* Item: `/catalog/<int:category_id>/items/<int:item_id>/JSON` (Displays a single item)

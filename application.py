#!/usr/bin/env python3
# Created by Jacob Schaible
# For the Udacity Full Stack Web Developer Nanodegree

from flask import Flask, render_template, request, redirect, url_for
from flask import flash, jsonify
from flask import session as login_session
from flask import make_response
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
import requests


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"


def connect():
    """ Makes connection with database.
        Returns: the DBSession
    """
    engine = create_engine('sqlite:///itemcatalog.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    return session


###################################
# Authentication Helper Functions #
###################################
@app.route('/login')
def showLogin():
    """ Create anti-forgery state token"""
    session = connect()
    categories = session.query(Category).all()
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, categories=categories)


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """ Handles FACEBOOK OAuth connection"""
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (  # noqa
          app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first
        index which gives us the key : value for the server access token
        then we split it on colons to pull out the actual token value and
        replace the remaining quotes with nothing so that it can be used
        directly in the graph api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session
    #  in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """ Handles FACEBOOK OAuth disconnect"""
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = ('https://graph.facebook.com/%s/permissions?access_token=%s' %
           (facebook_id, access_token))
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """ Handles GOOGLE OAuth connection"""
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                                 'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("You are now logged in as %s" % login_session['username'])
    print("Done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """ Handles GOOGLE OAuth disconnect.
        Revokes a current user's token and resets their login_session.
    """
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
                                 'Failed to revoke token for given user.',
                                 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/disconnect')
def disconnect():
    """ Disconnect based on provider.
        Checks if user is authorized with GOOGLE or FACEBOOK
        and calls the appropriate function.
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


#########################
# User Helper Functions #
#########################
def createUser(login_session):
    """ Creates a new user in the database
        Args: login_session
        Returns: newly assigned user.id of the user
    """
    session = connect()
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    """ Args: user_id: the user.id of the user to look up
        Returns: user object or None if user not found
    """
    session = connect()
    user = session.query(User).filter_by(id=user_id).one_or_none()
    return user


def getUserID(email):
    """ Args: email: the email address of the user to look up
        Returns: user.id of the user or None if user not found
    """
    session = connect()
    user = session.query(User).filter_by(email=email).one_or_none()
    return user.id


#########################
# JSON Helper Functions #
#########################
@app.route('/catalog/JSON')
def catalogJSON():
    """ Returns: JSON endpoint for catalog categories"""
    session = connect()
    catalog = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in catalog])


@app.route('/catalog/<int:category_id>/items/JSON')
def categoryJSON(category_id):
    """ Args: category_id: category.id of desired category
        Returns: JSON endpoint for category items
    """
    session = connect()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/catalog/<int:category_id>/items/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    """ Args: category_id: category.id of parent category
              item_id: item.id of desired item
        Returns: JSON endpoint for a single item
    """
    session = connect()
    item = session.query(Item).filter_by(category_id=category_id,
                                         id=item_id).one()
    return jsonify(Item=item.serialize)


#########################
# CRUD Helper Functions #
#########################
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    """ R - READ
        Show catalog main page which displays recently added items.
        Checks if user is authenticated and allows appropriate privileges.
        Returns: HTML of catalog main page
    """
    session = connect()
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(10).all()
    if 'username' not in login_session:
        return render_template('publicCatalog.html', categories=categories,
                               items=items)
    else:
        return render_template('catalog.html', categories=categories,
                               items=items)


@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCategory():
    """ C - CREATE a new category.
        Checks if user is authenticated and allows appropriate privileges.
        Returns: HTML of new category page
    """
    session = connect()
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    if request.method == 'POST':
        category = Category(name=request.form['name'],
                            user_id=login_session['user_id'])
        session.add(category)
        session.commit()
        flash("New category '%s' created!" % category.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html', categories=categories)


@app.route('/catalog/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    """ U - UPDATE a category.
        Checks if user is authenticated and allows appropriate privileges.
        Args: category_id: category.id of desired category
        Returns: HTML of edit category page
    """
    session = connect()
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if category.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert('You are not
            authorized to edit this category. Please create your own
            category in order to edit.');}
            </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        if request.form['name']:
            category.name = request.form['name']
            flash('Category renamed to %s!' % category.name)
        session.add(category)
        session.commit()
        return redirect(url_for('showCatalog'))
    return render_template('editCategory.html', category_id=category_id,
                           category=category, categories=categories)


@app.route('/catalog/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    """ D - DELETE a category
        Checks if user is authenticated and allows appropriate privileges
        Args: category_id: category.id of desired category
        Returns: HTML of delete category page
    """
    session = connect()
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if category.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert('You are not
            authorized to delete this category. Please create your
            own category in order to delete.');}
            </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        session.delete(category)
        session.commit()
        flash("Category %s deleted!" % category.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteCategory.html', category_id=category_id,
                               category=category, categories=categories)


@app.route('/catalog/<int:category_id>')
@app.route('/catalog/<int:category_id>/items')
def showCategory(category_id):
    """ R - READ
        Show category page which lists all items in that category.
        Checks if user is authenticated and allows appropriate privileges.
        Returns: HTML of category page
    """
    session = connect()
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(category.user_id)
    items = session.query(Item).filter_by(category_id=category.id).all()
    if ('username' not in login_session or
            creator is None or
            creator.id != login_session['user_id']):
        return render_template('publicCategory.html', category=category,
                               items=items, categories=categories)
    else:
        return render_template('showCategory.html', category=category,
                               items=items, categories=categories)


@app.route('/catalog/<int:category_id>/items/new', methods=['GET', 'POST'])
def newItem(category_id):
    """ C - CREATE a new item.
        Checks if user is authenticated and allows appropriate privileges.
        Args: category_id: category.id of parent category
        Returns: HTML of new item page
    """
    session = connect()
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    if category.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert('You are not
            authorized to create a new item here. Please create your
            own category in order to create.');}
            </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        newItem = Item(name=request.form['name'],
                       description=request.form['description'],
                       price=request.form['price'], category_id=category_id,
                       user_id=category.user_id)
        session.add(newItem)
        session.commit()
        flash("New item '%s' created!" % newItem.name)
        return redirect(url_for('showCategory', category_id=category_id,
                        categories=categories))
    else:
        return render_template('newItem.html', category_id=category_id,
                               categories=categories)


@app.route('/catalog/<int:category_id>/items/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(category_id, item_id):
    """ U - UPDATE an item.
        Checks if user is authenticated and allows appropriate privileges.
        Args: category_id: category.id of parent category
              item_id: item.id of desired item
        Returns: HTML of edit item page
    """
    session = connect()
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    item = session.query(Item).filter_by(category_id=category_id,
                                         id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if category.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert('You are not
            authorized to edit a new item here. Please create your
            own category in order to edit.');}
            </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
            flash("Item renamed to '%s'!" % item.name)
        if request.form['price']:
            item.price = request.form['price']
            flash("Item '%s' price changed to %s!" % (item.name, item.price))
        if request.form['description']:
            item.description = request.form['description']
            flash("Item '%s' description changed!" % item.name)
        session.add(item)
        session.commit()
        return redirect(url_for('showCategory', category_id=category_id,
                        categories=categories))
    else:
        return render_template('editItem.html', category_id=category_id,
                               item_id=item_id, item=item,
                               categories=categories)


@app.route('/catalog/<int:category_id>/items/<int:item_id>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    """ D - DELETE an item
        Checks if user is authenticated and allows appropriate privileges
        Args: category_id: category.id of parent category
              item_id: item.id of desired item
        Returns: HTML of delete item page
    """
    session = connect()
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).all()
    item = session.query(Item).filter_by(category_id=category_id,
                                         id=item_id).one()
    category = session.query(Category).filter_by(id=category_id).one()
    if category.user_id != login_session['user_id']:
        return """<script>function myFunction() {alert('You are not
            authorized to delete a new item here. Please create your
            own category in order to delete.');}
            </script><body onload='myFunction()'>"""
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Item '%s' deleted!" % item.name)
        return redirect(url_for('showCategory', category_id=category_id,
                        categories=categories))
    else:
        return render_template('deleteItem.html', category_id=category_id,
                               item_id=item_id, item=item,
                               categories=categories)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)


# Import for flask and SQLalchemy
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, joinedload
from setup_database import Base, Category, SubItem, User


# Import for Google Oauth - login_Session object will work as a
# dictionary to store values
from flask import session as login_session
import random,string


# import for Gconnect
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


# ---------------------------------------------------------
# ClientID
# ---------------------------------------------------------

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Item Application"


app = Flask(__name__)

engine = create_engine('sqlite:///catalogitemswithusers.db', connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create a state token to prevent request frogery.
# Store it in the session for later validation.
# ---------------------------------------------------------
# Functions for login handling
# ---------------------------------------------------------

@app.route('/login')
def showLogin():
    """
        Function to create anti-forgery state token
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    login_session['provider'] = 'google'

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
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;' \
              '-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s'), access_token
    print('User name is: ')
    print(login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'),401)
        response.headers['content-type'] = 'application/json'
        return response
    access_token = request.data

    app_id = json.loads(open('fb_client_secrets.json','r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json','r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?' \
          'grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

# --------------------------------------
# JSON APIs to show Catalog information
# --------------------------------------


@app.route('/catalog/catalog.json')
def catalogsJSON():
    """Returns JSON of all items in catalog"""
    categories = session.query(Category).all()
    items = session.query(SubItem).order_by(SubItem.id).all()
    data = []

    for c in categories:
        data.append(c.serialize)
        subdata = []
        for i in items:
            if i.category_id == c.id:
                subdata.append(i.serialize)
        item = {"Item": subdata}
        data.append(item)

    return jsonify(Category=data)


@app.route('/catalog/<int:category_id>/JSON')
def catalogSubItemJSON(category_id):
    """Returns JSON of all categories in catalog"""
    category = session.query(Category).options(
        joinedload(
            Category.items)).filter_by(
        id=category_id).all()
    return jsonify(
        Category=[
            dict(
                c.serialize,
                items=[
                    i.serialize for i in c.items]) for c in category])


# ---------------------------------------------------------
# Function shows all catalog items including latest 5 item
# ---------------------------------------------------------


@app.route('/')
@app.route('/categories/')
def showCategories():
    # return "This page will show all categories"
    categories = session.query(Category).all()
    latestItems = session.query(SubItem).order_by(
        SubItem.id.desc()).limit(5)
    if 'username' not in login_session:
        return render_template('publiccategories.html',
                               categories=categories,
                               latestItems=latestItems)
    else:
        return render_template('categories.html',
                               categories=categories,
                               latestItems=latestItems)


# ---------------------------------------------------------
# Function to create a new category
# ---------------------------------------------------------


@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    # return "This page will add new categories"
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id = login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash("new Category created!")
        return redirect(url_for('showCategories'))
    else:
        return render_template('newcategory.html')


# ---------------------------------------------------------
# Function to update/edit a category
# ---------------------------------------------------------


@app.route('/category/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    # return "This page will edit a category"
    editedCategory = session.query(Category).filter_by(id=category_id).one()
    if editedCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this category. Please create" \
               "your own category in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedCategory.name = request.form['name']
        session.add(editedCategory)
        session.commit()
        flash("Category edited successfully!")
        return redirect(url_for('showCategories'))
    else:
        return render_template(
            'editcategory.html', category_id=category_id, category = editedCategory)


# ---------------------------------------------------------
# Function to delete a category
# ---------------------------------------------------------


@app.route('/category/<int:category_id>/delete', methods = ['GET','POST'])
def deleteCategory(category_id):
    if 'username' not in login_session:
        return redirect('/login')
    # return "This page will delete a category"
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    categoryItems = session.query(SubItem).filter_by(
        category_id=category_id).all()
    if categoryToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this category. Please create" \
               "your own category in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        for categoryItem in categoryItems:
            session.delete(categoryItem)
        session.delete(categoryToDelete)
        session.commit()
        flash("category deleted successfully!")
        return redirect(url_for('showCategories'))
    else:
        return render_template(
            'deletedcategory.html', category_id=category_id, category=categoryToDelete)


# ---------------------------------------------------------
# Function shows all items in a specific category
# ---------------------------------------------------------


@app.route('/categories/<int:category_id>/')
@app.route('/categories/<int:category_id>/subitem/')
def showItem(category_id):
    categories = session.query(Category)
    # categoryId = session.query(Category).filter_by(id=category_id).one()
    # categoryid = categoryId.id
    categoryItems = session.query(SubItem).filter_by(
        category_id=category_id).all()
    categoryName = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(categoryName.user_id)
    count = session.query(SubItem).filter_by(
        category_id=category_id).count()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template(
            'publicitems.html',
            categories=categories,
            items=categoryItems,
            categoryName=categoryName,
            count=count,
            creator=creator)
    else:
        return render_template(
            'items.html',
            categories=categories,
            items=categoryItems,
            categoryName=categoryName,
            count=count,
            creator=creator)

# ---------------------------------------------------------
# Function shows specific information about that item
# ---------------------------------------------------------

@app.route('/catalog/<int:category_id>/<int:item_id>')
def showAboutItem(category_id, item_id):
    item = session.query(SubItem).filter_by(id=item_id).one()
    categoryName = session.query(Category).filter_by(id=category_id).one()
    creator = getUserInfo(categoryName.user_id)
    print item.description
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template(
            'publicshowitem.html',
            item=item,
            category_id=category_id)
    else:
        return render_template(
            'showitem.html',
            item=item,
            category_id=category_id)


# ---------------------------------------------------------
# Function to add a new Item
# ---------------------------------------------------------


@app.route('/categories/new', methods=['GET', 'POST'])
def newSubItem():
    if 'username' not in login_session:
        return redirect('/login')
    print "inside new item"
    categories = session.query(Category)
    if request.method == 'POST':
        print request.form['category_name']
        category_name = request.form['category_name']
        category_id = session.query(Category).filter_by(
            name=category_name).one()
        new_Item = SubItem(
            name=request.form['name'],
            description=request.form['description'],
            category_id=category_id.id,
            user_id=login_session['user_id'])
        session.add(new_Item)
        session.commit()
        flash("New Item %s Created successfully" % new_Item.name)
        return redirect(url_for('showCategories'))
    else:
        return render_template('newSubItem.html', categories=categories)
    # return "this page add a new item"


# ---------------------------------------------------------
# Function to update/edit SubItem information
# ---------------------------------------------------------


@app.route('/categories/<int:category_id>/<int:subitem_id>/edit', methods=['GET', 'POST'])
def editSubItem(category_id,subitem_id):
    if 'username' not in login_session:
        return redirect('/login')
    # return "This page will edit a subitem of a category"
    editedSubItem = session.query(SubItem).filter_by(id=subitem_id).one()
    if editedSubItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this sub item. Please create" \
               "your own subitem in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['name']:
            editedSubItem.name = request.form['name']
        if request.form['description']:
            editedSubItem.description = request.form['description']
        session.add(editedSubItem)
        session.commit()
        flash("subitem edited successfully!")
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template(
            'editsubitem.html', category_id=category_id, subitem_id=subitem_id, item=editedSubItem)


# ---------------------------------------------------------
# Function to delete a specific item from a category
# ---------------------------------------------------------


@app.route('/categories/<int:category_id>/<int:subitem_id>/delete', methods=['GET', 'POST'])
def deleteSubItem(category_id,subitem_id):
    if 'username' not in login_session:
        return redirect('/login')
    # return "This page will delete a subitem of a category"
    subitemToDelete = session.query(SubItem).filter_by(id=subitem_id).one()
    if subitemToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this subitem. Please create" \
               "your own sub item in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(subitemToDelete)
        session.commit()
        flash("subitem deleted successfully!")
        return redirect(url_for('showItem', category_id=category_id))
    else:
        return render_template('deletesubitem.html', subitem=subitemToDelete, category_id=category_id)


def getUserID(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return  user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id = user_id).one()
    return user


def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id

# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            flash("You have successfully been logged out.")

        elif login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']
            del login_session['user_id']
            del login_session['provider']
            flash("You have successfully been logged out.")
            return redirect(url_for('showCategories'))
        else:
            flash("You were not logged in")
    return redirect(url_for('showCategories'))


if __name__ == '__main__':
    app.secret_key='super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

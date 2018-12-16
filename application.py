#!/usr/bin/env python3
# Created by Jacob Schaible
# For the Udacity Full Stack Web Developer Nanodegree

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User
from flask import session as login_session
import random
import string

app = Flask(__name__)


# Connect to database
def connect():
    engine = create_engine('sqlite:///itemcatalog.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    return session


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


# JSON endpoint for catalog categories
@app.route('/catalog/JSON')
def catalogJSON():
    session = connect()
    catalog = session.query(Category).all()
    return jsonify(Categories=[c.serialize for c in catalog])


# JSON endpoint for category items
@app.route('/catalog/<int:category_id>/items/JSON')
def categoryJSON(category_id):
    session = connect()
    items = session.query(Item).filter_by(category_id = category_id).all()
    return jsonify(Items=[i.serialize for i in items])


# JSON endpoint for a single item
@app.route('/catalog/<int:category_id>/items/<int:item_id>/JSON')
def itemJSON(category_id, item_id):
    session = connect()
    item = session.query(Item).filter_by(category_id = category_id, id = item_id).one()
    return jsonify(Item=item.serialize)


# Show catalog main page
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    session = connect()
    categories = session.query(Category).all()
    items = session.query(Item).order_by(desc(Item.id)).limit(10).all()
    return render_template('catalog.html', categories=categories, items=items)


# Add new category
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newCategory():
    session = connect()
    categories = session.query(Category).all()
    if request.method == 'POST':
        category = Category(name = request.form['name'])
        session.add(category)
        session.commit()
        flash("New category '%s' created!" % category.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html', categories=categories)


# Edit a category
@app.route('/catalog/<int:category_id>/edit', methods=['GET', 'POST'])
def editCategory(category_id):
    session = connect()
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            category.name = request.form['name']
            flash('Category renamed to %s!' % category.name)
        session.add(category)
        session.commit()
        return redirect(url_for('showCatalog'))
    return render_template('editCategory.html', category_id=category_id, category=category, categories=categories)


# Delete a category
@app.route('/catalog/<int:category_id>/delete', methods=['GET', 'POST'])
def deleteCategory(category_id):
    session = connect()
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    if request.method == 'POST':
        session.delete(category)
        session.commit()
        flash("Category %s deleted!" % category.name)
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteCategory.html', category_id=category_id, category=category, categories=categories)


# Show a category
@app.route('/catalog/<int:category_id>')
@app.route('/catalog/<int:category_id>/items')
def showCategory(category_id):
    session = connect()
    categories = session.query(Category).all()
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return render_template('showCategory.html', category=category, items=items, categories=categories)


# Add a new item
@app.route('/catalog/<int:category_id>/items/new', methods=['GET', 'POST'])
def newItem(category_id):
    session = connect()
    categories = session.query(Category).all()
    if request.method == 'POST':
        newItem = Item(name = request.form['name'], description = request.form['description'],
            price = request.form['price'], category_id = category_id)
        session.add(newItem)
        session.commit()
        flash("New item '%s' created!" % newItem.name)
        return redirect(url_for('showCategory', category_id = category_id, categories=categories))
    else:
        return render_template('newItem.html', category_id = category_id, categories=categories)


# Edit an item
@app.route('/catalog/<int:category_id>/items/<int:item_id>/edit', methods=['GET', 'POST'])
def editItem(category_id, item_id):
    session = connect()
    categories = session.query(Category).all()
    item = session.query(Item).filter_by(category_id = category_id, id = item_id).one()
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
        return redirect(url_for('showCategory', category_id = category_id, categories=categories))
    else:
        return render_template('editItem.html', category_id = category_id, item_id = item_id, item=item, categories=categories)


# Delete an item
@app.route('/catalog/<int:category_id>/items/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteItem(category_id, item_id):
    session = connect()
    categories = session.query(Category).all()
    item = session.query(Item).filter_by(category_id = category_id, id = item_id).one()
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash("Item '%s' deleted!" % item.name) 
        return redirect(url_for('showCategory', category_id = category_id, categories=categories))
    else:
        return render_template('deleteItem.html', category_id = category_id, item_id = item_id, item=item, categories=categories)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
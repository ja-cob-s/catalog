#!/usr/bin/env python3
#Created by Jacob Schaible
#For the Udacity Full Stack Web Developer Nanodegree

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

app = Flask(__name__)


#Connect to database
def connect():
    engine = create_engine('sqlite:///itemcatalog.db')
    Base.metadata.bind = engine
    DBSession = sessionmaker(bind = engine)
    session = DBSession()
    return session


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
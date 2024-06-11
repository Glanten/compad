from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
# from pymongo.mongo_client import MongoClient
# from pymongo.server_api import ServerApi

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# +++ Database and SQL +++
db = SQL("sqlite:///compad.db")


# Can't remember what this does...?
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# ++++++++++++++++++++++++++++++++++++++++++++++
# +++ Flask and Webpages +++

# Main pages
@app.route("/")
# @login_required
def index():
    return render_template("index.html")

@app.route("/credits")
def credits():
    return render_template("credits.html")

@app.route("/system")
def system():
    return render_template("system.html")

@app.route("/starmap")
def starmap():
    return render_template("starmap.html")

@app.route("/compad")
def compad():
    return render_template("compad.html")

# Error: 404 page
@app.errorhandler(404)
def notfound(e):
    return render_template("404.html")

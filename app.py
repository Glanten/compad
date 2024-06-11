from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required
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
@login_required
def index():
    return render_template("index.html")

# register a new user
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register a new user (intended for initial setup only)"""
    if request.method == "POST":
        # if user hits register button on form...
        # create lower-case version of username
        submitted_username = request.form.get("username").lower()

        # query database for username match
        existing_name = db.execute(
            "SELECT * FROM users WHERE username = ?", submitted_username
        )
        if existing_name:
            # if <existing_name> returns anything, a record must already exist
            return render_template("error.html")
        # ensure a username was submitted
        if not request.form.get("username"):
            return render_template("error.html")
        # ensure a password was submitted
        elif not request.form.get("password"):
            return render_template("error.html")
        # ensure password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return render_template("error.html")
        
        # register the user
        else:
            hashed_password = generate_password_hash(
                request.form.get("password"), method='scrypt', salt_length=16)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                       submitted_username, hashed_password)
            return render_template("login.html")
        
    else:
    # user arrived by GET (i.e. typed in URL or via link) instead of POST, display registration page
    # send user to appropriate web page
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """User login - requires username and password"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html")
        
        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("error.html")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return render_template("error.html")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # If all went well, redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
    
@app.route("/logout")
def logout():
    """User gets logged out"""
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")

@app.route("/admin")
def admin():
    return render_template("admin.html")

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

# Error page
@app.errorhandler(404)
def notfound(e):
    return render_template("error.html")
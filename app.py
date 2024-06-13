from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# +++ Database and SQL +++
db = SQL("sqlite:///compad.db")

# insert admin status as argument/variable to every page
@app.context_processor
def inject_admin_status():
    admin_status = session.get("admin", 0)
    return dict(admin=admin_status)


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
@login_required
def register():
    """Register a new user"""
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
            return render_template("error.html", error_message="username already exists")
        # ensure a username was submitted
        if not request.form.get("username"):
            return render_template("error.html", error_message="no username submitted")
        # ensure a password was submitted
        elif not request.form.get("password"):
            return render_template("error.html", error_message="no password submitted")
        # ensure password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return render_template("error.html", error_message="passwords do not match")
        
        # register the user
        else:
            hashed_password = generate_password_hash(
                request.form.get("password"), method='scrypt', salt_length=16)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)",
                       submitted_username, hashed_password)
            return redirect("/admin")
        
    else:
    # user arrived by GET (i.e. typed in URL or via link) instead of POST, display registration page
    # send user to appropriate web page
        return redirect("/admin")

@app.route("/login", methods=["GET", "POST"])
def login():
    """User login - requires username and password"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("error.html", error_message="no username submitted")
        
        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("error.html", error_message="no password submitted")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return render_template("error.html", error_message="incorrect username or password")

        # Remember which user has logged in
        # Remember privilege level of logged in user (0 = user, 1 = admin)
        session["user_id"] = rows[0]["id"]
        session["admin"] = rows[0]["admin"]

        # If all went well, redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")
    
@app.route("/logout")
@login_required
def logout():
    """User gets logged out"""
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")

@app.route("/admin")
@login_required
def admin():
    """Show all users, their credits, and their admin status"""
    # check if session's admin attribute is valid (0 = user, 1 = admin)
    if session.get("admin") != 1:
        # if user is not admin, send them to error page
        return render_template("error.html", error_message="administrator access only")
    
    # if user is admin...
    # get list of users and send them to admin page
    user_list = db.execute("SELECT username, credits, admin, campaign FROM users ORDER BY id")
    # get list of credstick and send them to admin page
    credsticks_list = db.execute("SELECT code, credits, state, message FROM credsticks ORDER BY id")
    return render_template("admin.html", user_list=user_list, credsticks_list=credsticks_list)

@app.route("/credits")
@login_required
def credits():
    """Show user's credits, financial history, and allow sending/receiving of credits"""
    # create variable to hold user's current balance
    credits_balance = db.execute("SELECT credits FROM users WHERE id = ?", session["user_id"])[0]["credits"]
    
    # function here to compile financial history from database

    # function here to send credits (to a PC or NPC in your campaign); add to financial history table

    # function here to take credits from a credstick; add to financial history table

    return render_template("credits.html", credits_balance=credits_balance)

@app.route("/credits_send")
@login_required
def credits_send():
    """Transfer credits from user balance to other user's balance"""
    # create variables from submitted form
    send_recipient = request.form.get("send_credits_to")
    send_amount = int(request.form.get("send_credits_amount"))
    send_message = request.form.get("send_credits_note")
    # check values

    # send credits (update sender's and receiver's user tables)

    # update financialhistory table appropriately

    return redirect("/credits")

# create new credstick
@app.route("/credstick", methods=["GET", "POST"])
@login_required
def credstick():
    """Create new credstick for issue"""
    # when user hits submit button on form...
    if request.method == "POST":
        submitted_credstick_code = request.form.get("credstick_code")
        submitted_credstick_value = int(request.form.get("credstick_credits"))
        submitted_credstick_message = request.form.get("credstick_message")
        # query database for credstick code match
        existing_code = db.execute(
            "SELECT * FROM credsticks WHERE code = ?", submitted_credstick_code
        )
        if existing_code:
            # the code must be unique
            return render_template("error.html", error_message="credstick code already in use")
        # ensure a code was submitted
        if not request.form.get("credstick_code"):
            return render_template("error.html", error_message="no credstick code submitted")
        # ensure a credits value was submitted
        elif not request.form.get("credstick_credits"):
            return render_template("error.html", error_message="no credits submitted")
        # ensure credstick does not have a negative value
        elif int(request.form.get("credstick_credits")) < 0:
            return render_template("error.html", error_message="credstick must not have negative value")
        # ensure a message was submitted
        elif not request.form.get("credstick_message"):
            return render_template("error.html", error_message="no message submitted")
        
        # create the new credstick
        else:
            db.execute("INSERT INTO credsticks (code, credits, message) VALUES(?, ?, ?)", submitted_credstick_code, submitted_credstick_value, submitted_credstick_message)
            return redirect("/admin")
        
    else:
    # user arrived by GET (i.e. typed in URL or via link) instead of POST, display registration page
    # send user to appropriate web page
        return redirect("/admin")

@app.route("/system")
@login_required
def system():
    return render_template("system.html")

@app.route("/starmap")
@login_required
def starmap():
    return render_template("starmap.html")

@app.route("/compad")
@login_required
def compad():
    return render_template("compad.html")

# Error page
@app.errorhandler(404)
def notfound(e):
    return render_template("error.html", error_message=e)
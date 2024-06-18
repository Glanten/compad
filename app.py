from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
import os
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


#++++++++++++++++++++++++++#
#+++ Flask and Webpages +++#
#++++++++++++++++++++++++++#

# Main pages
@app.route("/")
@login_required
def index():
    return render_template("index.html")

#--- ADMIN ---#

@app.route("/admin")
@login_required
def admin():
    """Show all users, their credits, and their admin status"""
    # check if session's admin attribute is valid (0 = user, 1 = admin)
    if session.get("admin") != 1:
        # if user is not admin, send them to error page
        return render_template("error.html", error_message="administrator access only")
    
    # otherwise, if user is admin...
    # get list of users and send them to admin page
    user_list = db.execute("SELECT * FROM users ORDER BY id")
    
    # get list of credstick and send them to admin page
    credsticks_list = db.execute("SELECT * FROM credsticks ORDER BY id")

    # get list of starmap image URLs and send them to admin page
    starmaps_directory = os.path.join(app.static_folder, 'starmaps')
    starmap_urls = [file for file in os.listdir(starmaps_directory) if file.endswith('.jpg')]
    # get list of starmaps and send them to admin page
    starmaps_list = db.execute("SELECT * FROM starmaps ORDER BY id")
    return render_template("admin.html", user_list=user_list, credsticks_list=credsticks_list, starmap_urls=starmap_urls, starmaps_list=starmaps_list)

@app.route("/remove_user/<int:del_user_id>", methods=['POST'])
@login_required
def remove_user(del_user_id):
    """Delete user entry from database"""
    # remove entry from database according to submitted id
    db.execute("DELETE FROM users WHERE id = ?", del_user_id)
    return redirect("/admin")

@app.route("/edit_user/<int:edit_user_id>", methods=['GET', 'POST'])
@login_required
def edit_user(edit_user_id):
    """Permit admins to edit users' details"""
    # fetch user from database
    edited_user = db.execute("SELECT * FROM users WHERE id = ?", edit_user_id)[0]

    if request.method == 'POST':
        # check new username has been submitted
        if request.form.get("new_username"):
            new_username = request.form.get("new_username").lower()
            existing_name = db.execute("SELECT * FROM users WHERE username = ?", new_username)
            if existing_name:
                # if <existing_name> returns anything, a record must already exist
                return render_template("error.html", error_message="username already exists")
            else:
                db.execute("UPDATE users SET username = ? WHERE id = ?", new_username, edit_user_id)

        if request.form.get("new_password"):
            new_hashed_password = generate_password_hash(request.form.get("new_password"), method='scrypt', salt_length=16)
            db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hashed_password, edit_user_id)

        if request.form.get("new_credits"):
            new_credits = int(request.form.get("new_credits"))
            db.execute("UPDATE users SET credits = ? WHERE id = ?", new_credits, edit_user_id)
        
        if request.form.get("new_campaign"):
            new_campaign = int(request.form.get("new_campaign"))
            db.execute("UPDATE users SET campaign = ? WHERE id = ?", new_campaign, edit_user_id)

        if request.form.get("new_admin_status"):
            new_admin_status = int(request.form.get("new_admin_status"))
            if new_admin_status > 1 or new_admin_status < 0:
                return render_template("error.html", error_message="invalid admin status input")
            else:
                db.execute("UPDATE users SET admin = ? WHERE id = ?", new_admin_status, edit_user_id)

        return redirect("/admin")
    
    else:
        # take admin to edit_user page
        # function here to compile financial history from database
        this_user = db.execute("SELECT username FROM users WHERE id = ?", edit_user_id)[0]['username']
        this_user_finance_history = db.execute("SELECT * FROM financehistory WHERE isfrom = ? OR isto = ? ORDER BY id", this_user, this_user)
        logged_in_user_id = session['user_id']

        return render_template("edit_user.html", edited_user=edited_user, this_user_finance_history=this_user_finance_history, logged_in_user_id=logged_in_user_id)

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
        existing_name = db.execute("SELECT * FROM users WHERE username = ?", submitted_username)
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
    # user arrived by GET (i.e. typed in URL or via link) instead of POST, take them to admin page
        return redirect("/admin")
    
#--- LOGIN / LOGOUT ---#

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

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    """Permit changes to logged-in user's account """
    if request.method == 'POST':
        # check to see if current password was submitted
        if not request.form.get("old_password"):
            return render_template("error.html", error_message="current password not provided")
        
        # check to see if new password was submitted
        if not request.form.get("new_password"):
            return render_template("error.html", error_message="new password not provided")
        
        # ensure new password and confirmation password match
        if request.form.get("new_password") != request.form.get("confirmation"):
            return render_template("error.html", error_message="passwords do not match")
        
        # check to see if old password is correct
        current_user = db.execute("SELECT * FROM users WHERE id = ?", session['user_id'])
        if not check_password_hash(current_user[0]['hash'], request.form.get("old_password")):
            return render_template("error.html", error_message="current password incorrect")
        
        # otherwise, update the user
        new_password = generate_password_hash(request.form.get("new_password"), method='scrypt', salt_length=16)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_password, session['user_id'])
        return redirect("/")
    else:
        return render_template("account.html")

#--- CREDITS ---#

@app.route("/credits")
@login_required
def credits():
    """Show user's credits, financial history, and allow sending/receiving of credits"""
    # create variable to hold user's current balance
    credits_balance = db.execute("SELECT credits FROM users WHERE id = ?", session["user_id"])[0]["credits"]

    # create list of available users to send to
    user_campaign = db.execute("SELECT campaign FROM users WHERE id = ?", session['user_id'])[0]['campaign']
    send_list = db.execute("SELECT username FROM users WHERE campaign = ? AND NOT id = ?", user_campaign, session['user_id'])
    
    # function here to compile financial history from database
    current_username = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']
    finance_history = db.execute("SELECT * FROM financehistory WHERE isfrom = ? OR isto = ? ORDER BY id", current_username, current_username)

    return render_template("credits.html", credits_balance=credits_balance, send_list=send_list, finance_history=finance_history)

# send credits to NPC or other player
@app.route("/credits_send", methods=["GET", "POST"])
@login_required
def credits_send():
    """Transfer credits from user balance to other user's balance"""
    if request.method == "POST":
        # if user hits "send" on 'send credits' form
        # create variables from submitted form
        send_user = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']
        send_recipient = request.form.get("send_credits_to")
        send_amount = int(request.form.get("send_credits_amount"))
        send_message = request.form.get("send_credits_note")
        
        # check values
        # serverside value error checking
        if not request.form.get("send_credits_to"):
            return render_template("error.html", error_message="you must select a recipient to send credits to")
        if not request.form.get("send_credits_amount"):
            return render_template("error.html", error_message="you must select an appropriate amount of credits to send")
        if not request.form.get("send_credits_note"):
            return render_template("error.html", error_message="please include a message when sending credits, this helps the sender and receiver identify the transaction")
        if send_amount < 1:
            return render_template("error.html", error_message="cannot send zero or negative-value credits")
        
        # match recipient on form with recipient in database, use id to select
        if send_recipient != "NPC":
            database_recipient = db.execute("SELECT id FROM users WHERE username = ?", send_recipient)
            if not database_recipient:
                return render_template("error.html", error_message="no such recipient found in database")
            
            recipient_campaign = db.execute("SELECT campaign FROM users WHERE username = ?", send_recipient)
            user_campaign = db.execute("SELECT campaign FROM users WHERE id = ?", session['user_id'])
            if recipient_campaign != user_campaign:
                return render_template("error.html", error_message="users not in same campaign")
            
            database_recipient_id = db.execute("SELECT id FROM users WHERE username = ?", send_recipient)[0]['id']
            if database_recipient_id == session['user_id']:
                return render_template("error.html", error_message="cannot send credits to self")
        
        # check user has enough credits to send
        user_current_balance = int(db.execute("SELECT credits FROM users WHERE id = ?", session["user_id"])[0]['credits'])
        if user_current_balance < send_amount:
            return render_template("error.html", error_message="you do not have enough credits to send")

        # update sender's balance
        user_new_balance = user_current_balance - send_amount
        db.execute("UPDATE users SET credits = ? WHERE id = ?", user_new_balance, session["user_id"])
        # update recipient's balance
        if send_recipient != "NPC":
            recipient_current_balance = int(db.execute("SELECT credits FROM users WHERE id = ?", database_recipient_id)[0]['credits'])
            recipient_new_balance = recipient_current_balance + send_amount
            db.execute("UPDATE users SET credits = ? WHERE id = ?", recipient_new_balance, database_recipient_id)

        # update financialhistory table appropriately
        db.execute(
            "INSERT INTO financehistory (isfrom, isto, value, message) VALUES (?, ?, ?, ?)", send_user, send_recipient, send_amount, send_message
            )
        return redirect("/credits")

    else:
        # user arrived by GET (i.e. via link or typed URL), send them to credits page
        return redirect("/credits")

# acquire credits from a credstick code
@app.route("/credits_receive", methods=["GET", "POST"])
@login_required
def credits_receive():
    """Acquire credits from a unique credstick code"""
    if request.method == "POST":
        # if user hits "send" on 'send credits' form
        # create variables from submitted form
        receive_code = request.form.get("input_credstick_code")

        # check values
        if not request.form.get("input_credstick_code"):
            return render_template("error.html", error_message="no credstick code detected")
        
        # match input credstick code with database
        database_credstick = db.execute("SELECT * FROM credsticks WHERE code = ?", receive_code)
        if not database_credstick:
            return render_template("error.html", error_message="invalid credstick code")
        
        # check code is active (i.e. not yet redeemed)
        if int(database_credstick[0]['state']) != 0:
            return render_template("error.html", error_message="credstick already redeemed")
        
        # update user's balance
        user_current_balance = int(db.execute("SELECT credits FROM users WHERE id = ?", session["user_id"])[0]['credits'])
        credstick_value = int(db.execute("SELECT credits FROM credsticks WHERE code = ?", receive_code)[0]['credits'])
        credstick_message = db.execute("SELECT message FROM credsticks WHERE code = ?", receive_code)[0]['message']
        user_new_balance = user_current_balance + credstick_value

        db.execute(
            "UPDATE users SET credits = ? WHERE id = ?", user_new_balance, session['user_id']
            )

        # update credstick's state to 'redeemed' (i.e. 0 = valid, 1 = redeemed)
        db.execute("UPDATE credsticks SET state = 1 WHERE code = ?", receive_code)

        # update financehistory accordingly
        recipient_username = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']
        db.execute(
            "INSERT INTO financehistory (isfrom, isto, value, message) VALUES ('NPC', ?, ?, ?)", recipient_username, credstick_value, credstick_message
            )

        return redirect("/credits")
    
    else:
        # user arrived by GET (i.e. via link or typed URL), send them to credits page
        return redirect("/credits")

# create new credstick
@app.route("/credstick", methods=['GET', 'POST'])
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
    
@app.route("/remove_credstick/<int:credstick_id>", methods=['POST'])
@login_required
def remove_credstick(credstick_id):
    """Delete credstick entry from database"""
    # remove entry from database according to submitted id
    db.execute("DELETE FROM credsticks WHERE id = ?", credstick_id)
    return redirect("/admin")

#--- SYSTEM MAPS ---#

@app.route("/system")
@login_required
def system():
    return render_template("system.html")

#--- STARCHARTS ---#

@app.route("/starmap")
@login_required
def starmap():
    """Show starcharts user has unlocked, allow user to unlock new charts with a code"""
    # create variable to list user's unlocked charts

    return render_template("starmap.html")

@app.route("/starmap_creation", methods=['GET', 'POST'])
@login_required
def starmap_creation():
    """Make a new starmap code"""
    # when user hits submit button on form...
    if request.method == 'POST':
        submitted_starmap_code = request.form.get("starmap_code")
        submitted_starmap_name = request.form.get("starmap_mapname")
        submitted_starmap_url = request.form.get("starmap_url")
        #query database for existing name or code match
        existing_starmap_code = db.execute("SELECT * FROM starmaps WHERE code = ?", submitted_starmap_code)
        existing_starmap_name = db.execute("SELECT * FROM starmaps WHERE mapname = ?", submitted_starmap_name)
        if existing_starmap_code:
            # the starmap code must be unique
            return render_template("error.html", error_message="starmap code already in use")
        elif existing_starmap_name:
            # the starmap name must be unique
            return render_template("error.html", error_message="starmap name already in use")
        else:
            # ensure a code was submitted
            if not request.form.get("starmap_code"):
                return render_template("error.html", error_message="no starmap code submitted")
            elif not request.form.get("starmap_mapname"):
                return render_template("error.html", error_message="no starmap name submitted")
            elif not request.form.get("starmap_url"):
                return render_template("error.html", error_message="no starmap filename submitted")
            # create the new starmap
            else:
                db.execute("INSERT INTO starmaps (mapname, url, code) VALUES (?, ?, ?)", submitted_starmap_name, submitted_starmap_url, submitted_starmap_code)
                return redirect("/admin")
    else:
    # user arrived by GET (i.e. typed in URL or via link) instead of POST, send user to appropriate web page
        return redirect("/admin")

@app.route("/remove_starmap_code/<int:starmap_id>", methods=['POST'])
@login_required
def remove_starmap_code(starmap_id):
    """Delete starmap code entry from database"""
    # remove entry from database according to submitted id
    db.execute("DELETE FROM starmaps WHERE id = ?", starmap_id)
    return redirect("/admin")

@app.route("/starmap_unlock", methods=['GET', 'POST'])
@login_required
def starmap_unlock():
    # user arrived by post (i.e. submitted form)
    if request.method == "POST":
        # TO DO!
        return render_template("starmap.html")
    else:
        # user arrived by GET (i.e. via link or typed URL), send them to the starmap page
        return render_template("starmap.html")

#--- DID YOU GET MY WAVE? ---#

@app.route("/compad")
@login_required
def compad():
    return render_template("compad.html")

# Error page
@app.errorhandler(404)
def notfound(e):
    return render_template("error.html", error_message=e)
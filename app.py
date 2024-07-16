from cs50 import SQL
from flask import Flask, redirect, render_template, request, session, send_file
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


# ensure content is always fresh and not an old (potentially outdated) cached version
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# provide count of unread messages in compad inbox
# provide user's colour scheme
@app.context_processor
def inject_user_variables():
    """Get user's colour chosen scheme and get count of unread messages for every page"""
    # safely define/default variables
    total_unread_messages = 0
    user_colour_scheme = "colour_scheme_purplestars.css"

    if 'user_id' in session:
        logged_in_user_id = session['user_id']
        user_msg_table = f"msg{logged_in_user_id}"

        # construct SQL query for compad message count
        read_state_query = f"SELECT COUNT(readState) FROM {user_msg_table} WHERE readState = 0;"
        unread_result = db.execute(read_state_query)

        # construct SQL query for colour scheme
        visuals_query = f"SELECT scheme FROM users WHERE id = {logged_in_user_id}"
        visual_result = db.execute(visuals_query)

        # error checking and formatting for compad message count
        if unread_result and unread_result[0]['COUNT(readState)'] is not None:
            if unread_result[0]['COUNT(readState)'] > 99:
                total_unread_messages = "99+"
            else:
                total_unread_messages = unread_result[0]['COUNT(readState)']

        # error checking and formatting for colour scheme
        if visual_result and visual_result[0]['scheme'] is not None:
            user_colour_scheme = visual_result[0]['scheme']

    # return the values as dicts
    return {'total_unread_messages': total_unread_messages, 'user_colour_scheme': user_colour_scheme}

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

    # get list of starmap image URLs
    starmap_directory = os.listdir(os.path.join(app.static_folder, 'starmaps'))
    starmap_urls = [file for file in starmap_directory if file.endswith('.jpg')]
    # get starmap database
    starmap_db = db.execute("SELECT * FROM starmaps;")
    # get starmap database urls
    starmap_db_urls = []
    for db_entry in starmap_db:
        starmap_db_urls.append(db_entry["url"])
    # get list of unassigned starmap urls
    unassigned_starmaps = []
    for instance in starmap_urls:
        if instance not in starmap_db_urls:
            unassigned_starmaps.append(instance)
    
    return render_template(
        "admin.html",
        user_list=user_list,
        credsticks_list=credsticks_list,
        unassigned_starmaps=unassigned_starmaps,
        starmap_db=starmap_db,
        )

@app.route("/remove_user/<int:del_user_id>", methods=['POST'])
@login_required
def remove_user(del_user_id):
    """Delete user entry from database"""
    # remove entry from database according to submitted id
    db.execute("DELETE FROM users WHERE id = ?", del_user_id)
    # also remove user's message table from database
    deleted_user_compad_table_name = "msg" + str(del_user_id)
    db.execute("DROP TABLE ?", deleted_user_compad_table_name)
    return redirect("/admin")

@app.route("/edit_user/<int:edit_user_id>", methods=['GET', 'POST'])
@login_required
def edit_user(edit_user_id):
    """Permit admins to edit users' details"""
    logged_in_user_id = session['user_id']
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
        # compile financial history from database
        this_user = db.execute("SELECT username FROM users WHERE id = ?", edit_user_id)[0]['username']
        this_user_finance_history = db.execute("SELECT * FROM financehistory WHERE isfrom = ? OR isto = ? ORDER BY id", this_user, this_user)
        # compile starmap catalogue from database
        map_ids_in_inventory = db.execute("SELECT starmapid FROM starmapinventory WHERE userid = ?", edited_user["id"])
        user_map_inventory = []
        for item in map_ids_in_inventory:
            user_map_inventory.append(item["starmapid"])
        users_maps = []
        for row in user_map_inventory:
            users_maps.append(db.execute("SELECT * FROM starmaps WHERE id = ?", row)[0])

        return render_template(
            "edit_user.html",
            edited_user=edited_user,
            this_user_finance_history=this_user_finance_history,
            logged_in_user_id=logged_in_user_id,
            users_maps=users_maps
            )

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
            # create compad (i.e. mail) table for user in database
            this_user_id = db.execute("SELECT id FROM users WHERE username = ?", submitted_username)[0]['id']
            new_user_compad_tablename = "msg" + str(this_user_id)
            db.execute("CREATE TABLE ? (msgId INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, userId INTEGER NOT NULL DEFAULT ?, toUser TEXT NOT NULL, fromUser TEXT NOT NULL, message TEXT NOT NULL, readState INTEGER DEFAULT 0, archive INTEGER DEFAULT 0);", new_user_compad_tablename, this_user_id)
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
        # method was GET, therefore arrived by URL or entering address manually
        # get list of stylesheets
        static_folder = os.listdir(os.path.join(app.static_folder))
        stylesheets = []
        for sheet in static_folder:
            if sheet.endswith('.css'):
                if sheet != 'style_default.css':
                    stylesheets.append(sheet)
        
        return render_template("account.html", stylesheets=stylesheets)
    
@app.route("/change_scheme", methods=['POST'])
@login_required
def change_scheme():
    """Change site colour scheme for user"""
    # get list of stylesheets
    static_folder = os.listdir(os.path.join(app.static_folder))
    stylesheets = []
    for sheet in static_folder:
        if sheet.endswith('.css'):
            if sheet != 'style_default.css':
                stylesheets.append(sheet)
    
    # error checking
    if not request.form.get("scheme_drop_down"):
        return render_template("error.html", error_message="no scheme submitted")
    else:
        selected_style = request.form.get("scheme_drop_down")
        # does selected style exist?
        if selected_style not in stylesheets:
            return render_template("error.html", error_message="colour scheme not found")

    # change stylesheet
    db.execute("UPDATE users SET scheme = ? WHERE id = ?", selected_style, session['user_id'])

    return redirect("/account")

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
    # get starmapids from starmapinventory
    current_user = session['user_id']
    map_ids_in_inventory = db.execute("SELECT starmapid FROM starmapinventory WHERE userid = ?", current_user)
    user_map_inventory = []
    for item in map_ids_in_inventory:
        user_map_inventory.append(item["starmapid"])
    
    users_maps = []
    for row in user_map_inventory:
        users_maps.append(db.execute("SELECT * FROM starmaps WHERE id = ?", row)[0])

    return render_template("starmap.html", users_maps=users_maps)

@app.route("/add_starmap", methods=['POST'])
@login_required
def add_starmap():
    """Add a starmap, via unlock code, to user's inventory"""
    # create variables from submitted info
    starmap_code = request.form.get("input_starmap_code")
    starmap_db = db.execute("SELECT * FROM starmaps;")
    current_user = session['user_id']
    valid_codes = []
    for entry in starmap_db:
        valid_codes.append(entry["code"])
    
    starmapinventory_db = db.execute("SELECT * FROM starmapinventory WHERE userid = ?;", current_user)
    current_entries = []
    for mention in starmapinventory_db:
        current_entries.append(mention["starmapid"])
    
    # validate input
    if not request.form.get("input_starmap_code"):
        return render_template("error.html", error_message="no starmap code detected")
    elif starmap_code not in valid_codes:
        return render_template("error.html", error_message="invalid code")
    else:
        starmap_to_add = db.execute("SELECT id FROM starmaps WHERE code = ?", starmap_code)[0]['id']
    
    if starmap_to_add in current_entries:
        return redirect("/starmap")
    else:
        db.execute("INSERT INTO starmapinventory (userid, starmapid) VALUES (?, ?)", current_user, starmap_to_add)
        return redirect("/starmap")

@app.route("/new_starmap_db_entry", methods=['POST'])
@login_required
def new_starmap_db_entry():
    """Create a new entry in the database's "starmaps" table"""
    # create variables from form information
    submitted_filename = request.form.get('new_starmap_entry_filename')
    valid_starmaps = os.listdir(os.path.join(app.static_folder, 'starmaps'))
    starmap_db = db.execute("SELECT * FROM starmaps;")
    existing_db_entries = []
    existing_db_codes = []
    for db_entry in starmap_db:
        existing_db_entries.append(db_entry["url"])
        existing_db_codes.append(db_entry["code"])
    submitted_code = request.form.get('new_starmap_entry_code')
    # check values
    if not request.form.get('new_starmap_entry_filename'):
        return render_template("error.html", error_message="no filename detected")
    elif submitted_filename not in valid_starmaps:
        return render_template("error.html", error_message="invalid filename submitted")
    elif submitted_filename in existing_db_entries:
        return render_template("error.html", error_message="starmap already entered in database")
    elif not request.form.get('new_starmap_entry_code'):
        return render_template("error.html", error_message="no code detected")
    elif submitted_code in existing_db_codes:
        return render_template("error.html", error_message="code already exists in database")
    else:
        db.execute("INSERT INTO starmaps (url, code) VALUES (?, ?)", submitted_filename, submitted_code)
    return redirect("/admin")

@app.route("/edit_starmap/<int:starmap_id>", methods=['POST'])
@login_required
def edit_starmap(starmap_id):
    """Change starmap code"""
    # create variables for submitted data
    edited_starmap_id = starmap_id
    edited_starmap_new_code = request.form.get("new_starmap_code")
    # validate data
    starmap_db = db.execute("SELECT * FROM starmaps;")
    codes_in_use = []
    valid_starmap_ids = []
    for entry in starmap_db:
        codes_in_use.append(entry["code"])
        valid_starmap_ids.append(entry["id"])
    if not request.form.get("new_starmap_code"):
        return render_template("error.html", error_message="no starmap code detected")
    elif edited_starmap_new_code in codes_in_use:
        return render_template("error.html", error_message="starmap code already in use")
    elif edited_starmap_id not in valid_starmap_ids:
        return render_template("error.html", error_message="invalid starmap id detected")
    else:
        # edit database with new code
        db.execute("UPDATE starmaps SET code = ? WHERE id = ?", edited_starmap_new_code, edited_starmap_id)
        return redirect("/admin")
    
@app.route("/remove_starmap/<int:starmap_id><int:user_id>", methods=['POST'])
@login_required
def remove_starmap(starmap_id, user_id):
    """Remove starmap from player inventory"""
    # validate data
    targetted_starmap = db.execute("SELECT * FROM starmapinventory WHERE starmapid = ? AND userid = ?", starmap_id, user_id)[0]
    if not targetted_starmap:
        return render_template("error.html", error_message="user/starmap combination not found in database")
    else:
        db.execute("DELETE FROM starmapinventory WHERE starmapid = ? AND userid = ?", starmap_id, user_id)
        return redirect("/admin")

# secure starmaps so they can only be viewed by people with the correct inventory (or admins)
@app.route("/static/starmaps/<starmap_url>", methods=['GET'])
@login_required
def view_starmap(starmap_url):
    """Ensure only admins and authorised users have access to starmaps"""
    # define filepath
    path_to_starmap = os.path.join(app.root_path, 'static', 'starmaps', starmap_url)

    # check if user has starmap in their inventory
    current_user = session['user_id']
    map_ids_in_inventory = db.execute("SELECT starmapid FROM starmapinventory WHERE userid = ?", current_user)
    user_map_inventory = []
    for item in map_ids_in_inventory:
        user_map_inventory.append(item["starmapid"])
    
    users_maps = []
    for row in user_map_inventory:
        users_maps.append(db.execute("SELECT url FROM starmaps WHERE id = ?", row)[0]['url'])

    # only allow access to starmap via direct URL if starmap is in user's inventory
    if session.get("admin") == 1 or starmap_url in users_maps:
        return send_file(path_to_starmap, mimetype='image/jpeg')
    else:
        return render_template("error.html", error_message="you do not have access to this starmap")

#--- DID YOU GET MY WAVE? ---#

@app.route("/compad", methods=['POST', 'GET'])
@login_required
def compad():
    """Display user's compad messages (primitive email system)"""
    # get appropriate database contents
    current_user = session['user_id']
    if request.method == 'POST':

        # ERROR CHECKING
        # ensure "To" field is not empty
        if not request.form.get("compose_recipient"):
            return render_template("error.html", error_message="No recipient detected")
        # no generic "NPC" recipient
        if request.form.get("compose_npc_name") == "NPC" and request.form.get("compose_recipient") == "NPC":
            return render_template("error.html", error_message="Please insert correct NPC name")
        # if user is sending to NPC, ensure an NPC name was entered
        if request.form.get("compose_recipient") == "NPC" and not request.form.get("compose_npc_name"):
            return render_template("error.html", error_message="Please enter a valid NPC name")
        # check for valid usernames in To: field
        valid_usernames = db.execute("SELECT username FROM users WHERE admin IS NOT 1;")
        valid_username_list = []
        for identity in valid_usernames:
            valid_username_list.append(identity["username"])
        if request.form.get("compose_recipient") != "NPC" and request.form.get("compose_recipient") not in valid_username_list:
            return render_template("error.html", error_message="Character not found in database")
        # ensure non-admin user's username is in the "From" field
        admin_status = session.get("admin", 0)
        current_username = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']
        if admin_status != 1:
            if request.form.get("compose_sender") != current_username:
                return render_template("error.html", error_message="From field contains incorrect data")
        # ensure "From" field is not empty
        if not request.form.get("compose_sender"):
            return render_template("error.html", error_message="No entry in From field")
        # ensure "Message" field is not empty
        if not request.form.get("compose_message"):
            return render_template("error.html", error_message="Cannot send blank message")
        
        # assign variables
        compose_sender = request.form.get("compose_sender")
        compose_message = request.form.get("compose_message")
        if request.form.get("compose_recipient") == "NPC":
            compose_recipient = request.form.get("compose_npc_name")
        else:
            compose_recipient = request.form.get("compose_recipient")
        
        # MESSAGES TO AN NPC
        user_msg_variable = "msg" + str(current_user)
        current_user_admin_state = db.execute("SELECT admin FROM users WHERE id = ?", current_user)[0]['admin']
        if request.form.get("compose_recipient") == "NPC":
            recipient_msgid = "msg1"
            # update admin's (i.e. user 1) messages
            db.execute("INSERT INTO ? (toUser, fromUser, message) VALUES(?, ?, ?)", recipient_msgid, compose_recipient, compose_sender, compose_message)
            if current_user_admin_state == 1:
                # if current user is an admin, do nothing else
                return redirect("/compad")
            else:
                # if current user is non-admin, update current user's messages too
                db.execute("INSERT INTO ? (toUser, fromUser, message) VALUES(?, ?, ?)", user_msg_variable, compose_recipient, compose_sender, compose_message)
                return redirect("/compad")
        elif request.form.get("compose_recipient") != "NPC":
            # MESSAGES TO A PC
            recipient_id = db.execute("SELECT id FROM users WHERE username = ?", compose_recipient)[0]['id']
            recipient_msgid = "msg" + str(recipient_id)
            # update sender's messages
            db.execute("INSERT INTO ? (toUser, fromUser, message) VALUES(?, ?, ?)", user_msg_variable, compose_recipient, compose_sender, compose_message)
            # update recipient's messages
            db.execute("INSERT INTO ? (toUser, fromUser, message) VALUES(?, ?, ?)", recipient_msgid, compose_recipient, compose_sender, compose_message)
            return redirect("/compad")

    else:
        # method must = GET (i.e. link or URL entry) - standard page display with messages, compose, etc.
        user_msg_variable = "msg" + str(current_user)
        current_username = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']
        user_messages = db.execute("SELECT * FROM ? WHERE userId = ? ORDER BY msgId DESC", user_msg_variable, current_user)
        # mark all current messages as read
        db.execute("UPDATE ? SET readState = 1 WHERE readState = 0", user_msg_variable)

        # list of characters in same campaign, for "send" list
        admin_status = session.get("admin", 0)
        if admin_status == 1:
            recipient_list = db.execute("SELECT username FROM users WHERE NOT id = ?", session['user_id'])
        else:
            user_campaign = db.execute("SELECT campaign FROM users WHERE id = ?", session['user_id'])[0]['campaign']
            recipient_list = db.execute("SELECT username FROM users WHERE campaign = ? AND NOT id = ?", user_campaign, session['user_id'])
        
        return render_template(
            "compad.html",
            user_messages=user_messages,
            current_username=current_username,
            recipient_list=recipient_list,
            )

# below function is ready, but no link currently exists to trigger it
@app.route("/archive_message/<int:msg_id>", methods=['POST'])
@login_required
def archive_message(msg_id):
    """Archive message to clean up inbox"""
    current_user = session['user_id']
    msg_variable = "msg" + str(current_user)
    # change message's archive status to 1
    db.execute("UPDATE ? SET archive = 1 WHERE msgid = ?", msg_variable, msg_id)
    return redirect("/compad")

#--- MISC PAGES ---#

# Error page
@app.errorhandler(404)
def notfound(e):
    return render_template("error.html", error_message=e)
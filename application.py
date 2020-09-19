import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user = db.execute("SELECT username FROM users WHERE id = :id", id = session["user_id"])
    rows = db.execute("SELECT * FROM Holdings where user = :user", user = user[0]['username'])

    holdings = []
    balance = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])[0]['cash']
    gTotal = balance

    #Gather all info about current stocks owned
    for row in rows:
        if row['shares'] == 0:
            continue
        stock = row['stock']
        shares = row['shares']
        shareVal = usd(lookup(row['stock'])["price"])
        tValue = shares * lookup(row['stock'])["price"]
        holdings.append([stock, shares, shareVal, usd(tValue)])
        gTotal += tValue

    return render_template("index.html", holdings = holdings, balance = usd(balance), gTotal = usd(gTotal))


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "GET":
        return render_template("buy.html")
    else:
        stock = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])
        username = db.execute("SELECT username FROM users WHERE id = :id", id = session["user_id"])

        #Check if stock exists and if num of shares is not 0
        if stock == "" or not lookup(stock):
            return apology("Requested stock does not exist")
        elif shares < 1 or isinstance(shares, int) == False:
            return apology("Must request at least one stock")

        #If user has enough $, update cash and record transaction. Otherwise send apology
        elif cash[0]['cash'] < shares * lookup(stock)["price"]:
            return apology("Not enough funds")
        else:
            #users and transactions table
            db.execute("UPDATE users SET cash = cash - :price WHERE id = :id", price = shares*lookup(stock)["price"], id = session["user_id"])
            db.execute("INSERT INTO transactions(user, b_s, stock, numShares, tPrice) VALUES (:user, 'bought', :stock, :shares, :tprice)",
            user = username[0]['username'], stock = stock, shares = shares, tprice = shares*lookup(stock)["price"])
            holdings = db.execute("SELECT stock FROM Holdings WHERE user = :user and stock = :stock", user = username[0]['username'], stock = lookup(stock)["symbol"])

            #holdings table
            if len(holdings) != 0:
                db.execute("UPDATE Holdings SET shares = shares + :nShares, tValue = tValue + :price WHERE user = :user AND stock = :stock",
                user = username[0]['username'], stock = lookup(stock)["symbol"], nShares = shares, price = shares*lookup(stock)["price"])
            else:
                db.execute("INSERT INTO Holdings (user, stock, shares, shareValue, tValue) VALUES (:user, :stock, :shares, :shareValue, :tValue)",
                user = username[0]['username'], stock = lookup(stock)["symbol"], shares = shares, shareValue = usd(lookup(stock)["price"]), tValue = shares*lookup(stock)["price"])
            return redirect("/")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")
    rows = db.execute("SELECT username FROM users WHERE username = :user", user = username)
    
    if len(rows) == 0 and len(username) > 0:
        return jsonify(True)
    else:
        return jsonify(False)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    user = db.execute("SELECT username FROM users WHERE id = :id", id = session["user_id"])
    rows = db.execute("SELECT * FROM transactions WHERE user = :user", user = user[0]['username'])

    transactions = []

    for row in rows:
        stock = lookup(row['stock'])["symbol"]
        transType = row['b_s']
        numShares = row['numShares']
        tPrice = usd(row['tPrice'])
        date = row['date']
        transactions.append([stock, transType, numShares, tPrice, date])

    return render_template("history.html", transactions = transactions)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        userInput = request.form.get("symbol")
        if userInput == "" or not lookup(userInput):
            return apology("That stock does not exist")
        stockInfo = []
        stockInfo.append(lookup(userInput)["name"])
        stockInfo.append(lookup(userInput)["symbol"])
        stockInfo.append(usd(lookup(userInput)["price"]))
        return render_template("quoted.html", stockInfo = stockInfo)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "GET":
        return render_template("register.html")
    else:
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        if len(rows) == 1:
            return apology("username has already been taken", 400)
        elif request.form.get("password") == "" or request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)
        else:
            db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
            username=request.form.get("username"), hash=generate_password_hash(request.form.get("password")))
            return redirect("/")
            
            
@app.route("/changepass", methods=["GET", "POST"])
@login_required
def changePass():
    "Change password"
    if request.method == "GET":
        return render_template("changepass.html")
    else:
        oldpass = request.form.get("oldpass")
        newpass = request.form.get("newpass")
        confirm = request.form.get("confirm")
        
        rows = db.execute("SELECT hash FROM users WHERE id = :id", id = session["user_id"])
        
        if check_password_hash(rows[0]['hash'], oldpass) == False:
            return apology("Old password incorrect")
        elif newpass != confirm:
            return apology("New passwords do not match")
        else:
            db.execute("UPDATE users SET hash = :newpass WHERE id = :id", id = session["user_id"], newpass = generate_password_hash(newpass))
            return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user = db.execute("SELECT username FROM users WHERE id = :id", id = session["user_id"])
    holdings = db.execute("SELECT stock FROM Holdings WHERE user = :user", user = user[0]['username'])

    if request.method == "GET":
        return render_template("sell.html", holdings = holdings)
    else:
        stock = lookup(request.form.get("symbol"))["symbol"]
        numShares = int(request.form.get("shares"))
        shareVal = lookup(request.form.get("symbol"))["price"]
        uHoldings = db.execute("SELECT * FROM Holdings WHERE user = :user AND stock = :stock", user = user[0]['username'], stock = stock)

        #user input error check
        if numShares == "" or numShares < 1:
            return apology("select how many shares to sell")
        elif numShares > uHoldings[0]['shares']:
            return apology("you do not have that many shares")
        elif not stock:
            return apology("must provide stock symbol")
        else:
            db.execute("UPDATE users SET cash = cash + :price WHERE id = :id", price = numShares * shareVal, id = session["user_id"])
            db.execute("INSERT INTO transactions (user, b_s, stock, numShares, tPrice) VALUES (:user, 'sold', :stock, :shares, :tPrice)",
            user = uHoldings[0]['user'], stock = stock, shares = numShares, tPrice = numShares*shareVal)
            db.execute("UPDATE Holdings SET shares = shares - :shares, tValue = tValue - :tPrice WHERE user = :user AND stock = :stock",
            shares = numShares, tPrice = numShares*shareVal, user = user[0]['username'], stock = stock)
            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

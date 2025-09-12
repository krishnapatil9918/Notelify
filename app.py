from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, make_response
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import random, string, os, logging, pathlib, requests, cachecontrol, datetime
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from google.oauth2 import id_token
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies, create_access_token,set_access_cookies
from dotenv import load_dotenv



logging.basicConfig(level=logging.DEBUG)


app = Flask(__name__)
load_dotenv()

app.config.update(TEMPLATES_AUTO_RELOAD=True)
app.jinja_env.auto_reload = True
app.secret_key = os.environ.get("SECRET_KEY")

# Configuration for Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'   # Mail server
app.config['MAIL_PORT'] = 587                 # Port for TLS
app.config['MAIL_USE_TLS'] = True             # Enable TLS
app.config['MAIL_USE_SSL'] = False            # SSL usually uses 465
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ( "flasknoteapp", os.environ.get('MAIL_USERNAME') )


app.config['JWT_SECRET_KEY'] = os.environ.get("JWT_SECRET_KEY") # can be same or different
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=9)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False  # True if HTTPS
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

jwt = JWTManager(app)

mail = Mail(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(client_secrets_file=client_secrets_file, 
                                     scopes= ["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
                                     redirect_uri = "http://127.0.0.1:5000/callback"
                                     )

def get_db():
    conn = sqlite3.connect("notes.db")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn 
    
# this make table in database
note_reciever = sqlite3.connect('notes.db')
note_reciever = get_db()
written = note_reciever.cursor()
written.execute('''CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    otp TEXT,
    is_verified INTEGER DEFAULT 0
);''')

written.execute('''CREATE TABLE IF NOT EXISTS noteapp(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);''')

note_reciever.commit()
note_reciever.close()

@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# this is the registeration page function
@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashpassword = generate_password_hash(password)

        user = sqlite3.connect("notes.db")
        user = get_db()
        user_connecting = user.cursor()
        user_connecting.execute("select email from users where email=?",(email,))
        c = user_connecting.fetchone()

        try:
            num = random.randint(100000, 999999)
            if c:
                user.close()
            else:
                user_connecting.execute(
                "INSERT INTO users(name, email, password, otp) VALUES (?, ?, ?, ?)",
                (name, email, hashpassword, str(num))
            )
            user.commit()
            session['email'] = email
            msg = Message(
                subject="Notelify OTP",
                recipients=[email],
                body=f"Hello {name},\n\nYour OTP code is {num}. It will expire in 5 minutes."
            )
            mail.send(msg)

            flash("Registered! Please check your Gmail for the OTP.")
            return redirect(url_for('verify_otp'))

        except Exception as e:
            flash("Email already exists or error occurred.")
            print(e)

    return render_template('register.html')


# ------------------ VERIFY OTP ------------------
@app.route('/verify', methods=['GET', 'POST'])
def verify_otp():
    if 'email' not in session:
        return redirect(url_for('register'))

    if request.method == 'POST':
        otp_input = request.form['otp']
        email = session['email']

        user = sqlite3.connect("notes.db")
        user = get_db()
        cur = user.cursor()
        cur.execute("SELECT otp FROM users WHERE email=?", (email,))
        row = cur.fetchone()

        if row and row[0] == otp_input:
            cur.execute("UPDATE users SET is_verified=1 WHERE email=?", (email,))
            user.commit()
            user.close()

            session.pop('email', None)
            
            access_token = create_access_token(identity=email)
            response = make_response(redirect('/login'))
            set_access_cookies(response, access_token)
            return response

    return render_template('otp.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')
            

@app.route('/loginuser', methods=['POST'])
def loginuser():
    email = request.form['email']
    password = request.form['password']

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, email, password FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()

    if not user:
        flash("Invalid email!")
        return redirect(url_for('login'))

    userid, db_email, db_password = user

    if not check_password_hash(db_password, password):
        flash("Incorrect password!")
        return redirect(url_for('login'))

    session['userid'] = userid
    session['email'] = db_email

    access_token = create_access_token(identity=db_email)
    response = make_response(redirect('/homepage'))  
    set_access_cookies(response, access_token)        
    return response


@app.route('/googlelogin')
def googlelogin():
    authorization_url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true", prompt="select_account")
    session["state"] = state
    return redirect(authorization_url) 



@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)
    if not session["state"] == request.args["state"]:
        abort(500)  

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")  
    session["name"] = id_info.get("name")
    session["email"] = id_info.get("email")

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE email=?", (session["email"],))
    existing_user = c.fetchone()

    if existing_user:
        userid = existing_user[0]
    else:
        # digits = string.digits
        # password = ''.join(random.choices(digits, k=6))
        password = None
        c.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (session["name"], session["email"], password)
        )
        conn.commit()
        userid = c.lastrowid

    session["userid"] = userid
    conn.close()

   
    access_token = create_access_token(identity=session["email"])

    response = make_response(redirect("/homepage"))
    set_access_cookies(response, access_token)
    return response

    
@app.route('/logout')
def logout():
    session.clear()
    response = make_response(redirect(url_for('login')))
    unset_jwt_cookies(response)
    return response

@app.route('/reset')
def reset():
    return render_template('reset_password.html')

          
@app.route('/reset_processing', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    user_db = get_db()
    user_connecting = user_db.cursor()
    user_connecting.execute("SELECT email, password FROM users WHERE email=?", (email,))
    c = user_connecting.fetchone()

    if not c:
        print("User found!")
        return redirect('/reset') 
    

    if new_password != confirm_password:
        print("Password do not match")
        return redirect('/reset')

    hashed_new_password = generate_password_hash(new_password)
    user_connecting.execute("UPDATE users SET password=? WHERE email=?", (hashed_new_password, email))
    user_db.commit()
    user_db.close()

    print("Password updated successfully!")
    return redirect('/login')
          

# this is for homepage and showing all the notes currently in noteapp and after adding in noteapp
@app.route('/homepage')
@jwt_required()
def index():
    
    current_user = get_jwt_identity()  
    print("JWT CREATED :",  current_user)
    
    
    if "userid" in session:
    
        conn = get_db()
        userid = session['userid']
        c = conn.cursor()
        c.execute("SELECT id, title, content FROM noteapp WHERE user_id=? ORDER BY id DESC", (userid,))
        notes = c.fetchall()
        conn.close()
        return render_template("index.html", result=notes)


# this is the note_adder function helps to add note in noteapp
@app.route('/add', methods=['POST'])
@jwt_required()
def note_adder():
    if 'email' not in session:  
        flash("Please log in first!")
        return redirect(url_for('login'))
    try:
        current_user = get_jwt_identity()  
        print("JWT CREATED :",  current_user)
        title = request.form["title"]
        content= request.form["content"]
        note_reciever = sqlite3.connect('notes.db')
        note_reciever = get_db()
        written = note_reciever.cursor()
        userid=session['userid']
        written.execute(
        "INSERT INTO noteapp (title, content,user_id) VALUES (?, ?,?)",
        (title, content,userid)
        )
        
        note_reciever.commit()
        note_reciever.close()
        return redirect('/homepage')
    except Exception as a:
        return "error"
    
    
# this is the note_deleter function helps to delete the specific note from noteapp
@app.route('/delete/<int:id>', methods=['POST'])
@jwt_required()
def note_deleter(id):
    if 'email' not in session:   
        flash("Please log in first!")
        return redirect(url_for('login'))
    try:
        current_user = get_jwt_identity()  
        print("JWT CREATED :",  current_user)
        note_reciever = sqlite3.connect('notes.db')
        note_reciever = get_db()
        written = note_reciever.cursor()
        written.execute(
        "delete from noteapp where id = ?",
        (id,)
        )
        note_reciever.commit()
        note_reciever.close()
        return redirect(url_for("index"))
    except Exception as a:
        print(a)


# this is the note_editor function help to edit the existing note in the noteapp
@app.route('/edit/<int:id>', methods=['GET','POST'])
@jwt_required()
def note_editor(id):
    if 'email' not in session:
        flash("Please log in first!")
        return redirect(url_for('login'))
    try:
        current_user = get_jwt_identity()  
        print("JWT CREATED :",  current_user)
        note_reciever = sqlite3.connect('notes.db')
        note_reciever = get_db()
        written = note_reciever.cursor()
        if request.method == "POST":
            title = request.form["title"]
            content = request.form["content"]
            written.execute(
            "UPDATE noteapp SET title = ?, content = ? WHERE id = ?",
            (title, content, id)
            )
            note_reciever.commit()
            note_reciever.close()
            return redirect(url_for("index"))
        else:
            written.execute("SELECT*FROM NOTEAPP WHERE ID=?",(id,))
            c = written.fetchone()
            note_reciever.close()
            return render_template("editor.html", note=c)
    except Exception as a:
         print("Error:", a)


if __name__ == '__main__':   
 app.run(debug = True)
 
 
 
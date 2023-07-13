from flask import Flask,render_template,url_for,request,session,logging,redirect,flash
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session,sessionmaker
from sqlalchemy.sql import text
from flask_login import login_user, login_required, logout_user, current_user, LoginManager
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# from models import User

from passlib.hash import sha256_crypt
# engine=create_engine("mysql+pymysql://u1653335_bim:4dm1nbim@alpenprastoyo.com/u1653335_bim")
# db=scoped_session(sessionmaker(bind=engine))




app = Flask(__name__)
app.secret_key = "RadheKrishna"
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://u1653335_bim:4dm1nbim@alpenprastoyo.com/u1653335_bim"
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

db = SQLAlchemy(app)

class User(db.Model,UserMixin):
    __tablename__ = 'prod_users'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(255))
    username = db.Column(db.String(255))
    password = db.Column(db.String(255))
    institute = db.Column(db.String(255))
    age = db.Column(db.Integer)
    role = db.Column(db.String(255))

    def __init__(self, name, username, password, institute, age, role):
        self.name = name
        self.username = username
        self.password = password
        self.institute = institute
        self.age = age
        self.role = role

def check_login():
    if 'username' in session:
        return ''
    else:
        return redirect(url_for('register'))
    
@app.route("/register",methods=['POST','GET'])
def register():
    if request.method=="POST":
        name=request.form.get("name")
        institute=request.form.get("institute")
        age=request.form.get("age")               
        username=request.form.get("username")
        password=request.form.get("password")
        confirm=request.form.get("confirm")
        secure_password=sha256_crypt.encrypt(str(password))
        role = "user"
        # usernamedata=db.execute(text("SELECT username FROM prod_users WHERE username=:username"),{"username":username}).fetchone()
        usernamedata = User.query.filter_by( username = username).first()
        if usernamedata is None:
            if password==confirm:
                my_data = User(name,username,secure_password,institute,age,role)
                db.session.add(my_data)
                db.session.commit()
                flash("You are registered and can now login","success")
                return redirect(url_for('login'))
            else:
                flash("password does not match","danger")
                return render_template('register.html')
        else:
            flash("user already existed, please login or contact admin","danger")
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route("/login",methods=["POST","GET"])
def login():
    if request.method=="POST":
        username=request.form.get("username")
        password=request.form.get("password")
        user = User.query.filter_by(username=username,password=password).first()
        # usernamedata=db.execute(text("SELECT username FROM prod_users WHERE username=:username"),{"username":username}).fetchone()
        # passworddata=db.execute(text("SELECT password FROM prod_users WHERE username=:username"),{"username":username}).fetchone()
        
        if user is None:
            flash('No username or incorrect password', category='error')
            return render_template('login.html')
        else:
                # session["log"]=True          
                # session["username"]=username 
                # session["password"]=password 
                login_user(user, remember=True)
                flash('Logged in successfully!', category='success')
                return redirect(url_for('dashboard')) #to be edited from here do redict to either svm or home
  
    
    return render_template('login.html')

@app.route("/dashboard")
def dashboard():
    if('username' not in session):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route("/project/add")
def project_add():
    if('username' not in session):
        return redirect(url_for('login'))
    
    return render_template('newproject.html')

@app.route("/logout")
def logout():
    session.clear()
    flash('You are now logged out', category='success')
    return redirect(url_for('login'))

@app.route("/", methods=["GET","POST"])
def home():
    return render_template('login.html')
if __name__ == '__main__':
    app.run(debug=True)
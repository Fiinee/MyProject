from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, current_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from models import User, db
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'secret-key-goes-here'
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    

 
@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profil'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profil'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')




@app.route('/regist', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
      # email = request.form['email'] 
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already taken')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username, password=hashed_password)#, email=email)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully')
            return redirect(url_for('login'))
    else:
         return render_template('regist.html')

@app.route('/profil') # AAAAAAA ВОРКАЕТ 
def profil():
    if current_user.is_authenticated:
        if request.method == 'GET':
            return render_template('profil.html', user=current_user)
        if request.method == 'POST':
            username = request.form['username']
           # email = request.form['email']
            user = User.query.filter_by(id=current_user.get_id()).first()
           # user.email = email
            user.username = username
            db.session.commit()  
            return redirect(url_for('profil'))     
    else:
        return redirect(url_for('login'))

@app.route('/leaders')
def leaders():
    return render_template('leaders.html')

@app.route('/rules')
def rules():
    return render_template('rules.html')

@app.route('/index')
def base():
    return render_template('index.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(400)
def page_badreq(e):
    return render_template('400.html'), 400

@app.errorhandler(405)
def page_notall(e):
    return render_template('405.html'), 405

@app.route('/402')
def page_402(e):
  return render_template('402.html') #почему на 402 ругается хостинг как записать по другому то 

@app.errorhandler(401)
def page_401(e):
    return render_template('401.html'), 401

@app.errorhandler(403)
def page_403(e):
  return render_template('402.html'), 403

@app.errorhandler(500)
def page_no500(e):
    return render_template('500.html'), 500

@app.errorhandler(502)
def page_502(e):
    return render_template('502.html'), 502

@app.errorhandler(501)
def page_501(e):
    return render_template('501.html'), 501

@app.errorhandler(503)
def page_503(e):
    return render_template('503.html'), 503

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port="8080")
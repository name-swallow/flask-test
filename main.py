# main.py
from flask_wtf.csrf import CSRFProtect
from flask import Flask, render_template, redirect, request, session, send_file, url_for
import re
import pymysql
import logging
from datetime import timedelta
import hashlib
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from captcha.image import ImageCaptcha
import random
import string

if not os.path.exists('log'):
    os.makedirs('log')

user_logger = logging.getLogger('user_login')
user_logger.setLevel(logging.INFO)
user_handler = logging.FileHandler('log/log.log')
user_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
user_handler.setFormatter(user_formatter)
user_logger.addHandler(user_handler)

admin_logger = logging.getLogger('admin_login')
admin_logger.setLevel(logging.INFO)
admin_handler = logging.FileHandler('log/admin.log')
admin_handler.setFormatter(user_formatter)
admin_logger.addHandler(admin_handler)

app = Flask(__name__, template_folder='templates')
app.permanent_session_lifetime = timedelta(hours=2)
app.secret_key = 'Your secret key'
db = pymysql.connect(host="localhost", user='your_username', password='your_password', database='database_name')
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["20 per minute", "100 per hour"])

# 生成验证码
@app.route('/generate_captcha')
def generate_captcha():
    # 生成5位数字验证码
    captcha_text = ''.join(random.choices(string.digits, k=5))
    image = ImageCaptcha(width=150, height=50)
    data = image.generate(captcha_text)
    session['captcha_text'] = captcha_text
    return send_file(data, mimetype='image/png')

@app.route("/")
def index():
    if 'username' not in session:
        return redirect("/login")
    else:
        return render_template('index.html')

@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("15 per minute")
def login():
    if request.method == "POST":
        # 获取表单数据
        username = request.form.get('username')
        password = request.form.get('password')
        captcha = request.form.get('captcha')
        session_captcha = session.get('captcha_text')
        
        # 验证验证码
        if not captcha or not session_captcha or captcha != session_captcha:
            return render_template('login.html', error='验证码错误')
        
        # 验证用户
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()
        
        if user:
            passwd = hashlib.md5(password.encode('utf-8')).hexdigest()
            if passwd == user[2]:
                session['username'] = username
                user_logger.info(f"{username}登陆成功")
                # 清除验证码
                session.pop('captcha_text', None)
                return redirect("/")
        
        user_logger.warning(f'用户 {username} 尝试登录失败')
        return render_template('login.html', error='用户名或密码错误')
    
    return render_template('login.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            return render_template("login.html", error="两次输入的密码不一致")

        passwd = hashlib.md5(password.encode('utf-8')).hexdigest()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user:
            return render_template("login.html", error="用户名已经存在")
        if not validate_password(password):
            return render_template("login.html", error="密码必须至少8个字符，包含大写字母、小写字母、数字、特殊字符")
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, passwd))
            db.commit()
            return render_template('login.html', message='注册成功，请登录')
        except Exception as e:
            db.rollback()
            return render_template('login.html', error=f'注册失败: {str(e)}')
    return redirect(url_for('login'))

@app.route("/logout")
def logout():
    if 'username' in session:
        username = session['username']
        user_logger.info(f"{username} 退出登录")
        session.pop('username')
    if 'admin' in session:
        admin = session['admin']
        admin_logger.info(f"{admin} 退出登录")
        session.pop('admin')
    # 退出登录时，清除验证码
    session.pop('captcha_text', None)
    return redirect("/login")

@app.route("/adminlogin", methods=['GET', 'POST'])
@limiter.limit("15 per minute")
def adminlogin():
    if request.method == "POST":
        captcha = request.form.get('captcha')
        session_captcha = session.get('captcha_text')

        if not captcha or not session_captcha or captcha != session_captcha:
            return render_template('adminlogin.html', error='验证码错误')

        username = request.form.get('username')
        password = request.form.get('password')
        cursor = db.cursor()
        cursor.execute("SELECT * FROM admins WHERE username=%s ", (username,))
        user = cursor.fetchone()
        passwd = hashlib.md5(password.encode('utf-8')).hexdigest()
        if user and passwd == user[2]:
            session['admin'] = username
            admin_logger.info(f"{username}登陆成功")
            # 验证成功后，清除验证码，防止重复使用
            session.pop('captcha_text', None)
            return redirect("/admin")
        else:
            admin_logger.warning(f'用户 {username} 尝试登录失败')
            return render_template('adminlogin.html', error='登陆失败')
    return render_template('adminlogin.html')

@app.route("/admin", methods=['GET', 'POST'])
def admin():
    if 'admin' not in session:
        return redirect("/adminlogin")
    cursor = db.cursor()
    if request.method == "POST":
        user_id = request.form.get('user_id')
        cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
        users = cursor.fetchall()
    else:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
    return render_template('admin.html', users=users)

def validate_password(password):
    if len(password) < 8:
        return False
    elif len(password) > 20:
        return False
    elif not re.search("[a-z]", password):
        return False
    elif not re.search("[0-9]", password):
        return False
    elif not re.search("[A-Z]", password):
        return False
    elif not re.search("[$#@]", password):
        return False
    else:
        return True

if __name__ == '__main__':
    app.run(debug=True)
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
db = pymysql.connect(host="localhost", user='root', password='root', database='database_name')
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)  # 移除 default_limits

# 生成验证码
@app.route('/generate_captcha')
def generate_captcha():
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
@limiter.limit("15 per minute")  # 仅限制此路由
def login():
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        captcha = request.form.get('captcha')
        session_captcha = session.get('captcha_text')

        if not captcha or not session_captcha or captcha != session_captcha:
            return render_template('login.html', error='验证码错误')

        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cursor.fetchone()

        if user:
            passwd = hashlib.md5(password.encode('utf-8')).hexdigest()
            if passwd == user[2] and user[3] == 1:  # 检查密码和状态（1为启用）
                session['username'] = username
                user_logger.info(f"{username} 登陆成功")
                session.pop('captcha_text', None)
                return redirect("/")
            else:
                user_logger.warning(f'用户 {username} 尝试登录失败')
                return render_template('login.html', error='用户名或密码错误，或用户已被禁用')

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
            cursor.execute("INSERT INTO users (username, password, is_active) VALUES (%s, %s, %s)", (username, passwd, 1))
            db.commit()
            session.pop('captcha_text', None)  # 清除 session 中的验证码，确保登录时刷新
            return redirect(url_for('login', message='注册成功，请登录'))  # 使用 redirect 跳转到 /login
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
        return redirect("/login")
    if 'admin' in session:
        admin = session['admin']
        admin_logger.info(f"{admin} 退出登录")
        session.pop('admin')
        session.pop('captcha_text', None)
        return redirect("/adminlogin")
    return redirect("/login")  # 如果没有会话，直接重定向到登录页

@app.route("/adminlogin", methods=['GET', 'POST'])
@limiter.limit("15 per minute")  # 仅限制此路由
def adminlogin():
    if request.method == "POST":
        captcha = request.form.get('captcha')
        session_captcha = session.get('captcha_text')

        if not captcha or not session_captcha or captcha != session_captcha:
            return render_template('adminlogin.html', error='验证码错误')

        username = request.form.get('username')
        password = request.form.get('password')
        cursor = db.cursor()
        cursor.execute("SELECT * FROM admins WHERE username=%s", (username,))
        user = cursor.fetchone()
        passwd = hashlib.md5(password.encode('utf-8')).hexdigest()
        if user and passwd == user[2]:
            session['admin'] = username
            admin_logger.info(f"{username} 登陆成功")
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

@app.route("/delete_user/<int:user_id>", methods=['POST'])
def delete_user(user_id):
    if 'admin' not in session:
        return redirect("/adminlogin")
    try:
        cursor = db.cursor()
        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        db.commit()
        admin_logger.info(f"管理员删除了用户 ID 为 {user_id} 的用户信息")
    except Exception as e:
        db.rollback()
        admin_logger.error(f"删除用户 ID 为 {user_id} 的用户信息时出错: {str(e)}")
    return redirect("/admin")

@app.route("/edit_user/<int:user_id>", methods=['POST'])
def edit_user(user_id):
    if 'admin' not in session:
        return redirect("/adminlogin")
    try:
        username = request.form.get('username')
        password = request.form.get('password')
        cursor = db.cursor()
        if password:
            passwd = hashlib.md5(password.encode('utf-8')).hexdigest()
            cursor.execute("UPDATE users SET username=%s, password=%s WHERE id=%s", (username, passwd, user_id))
        else:
            cursor.execute("UPDATE users SET username=%s WHERE id=%s", (username, user_id))
        db.commit()
        admin_logger.info(f"管理员修改了用户 ID 为 {user_id} 的信息")
    except Exception as e:
        db.rollback()
        admin_logger.error(f"修改用户 ID 为 {user_id} 的信息时出错: {str(e)}")
    return redirect("/admin")

@app.route("/batch_delete", methods=['POST'])
def batch_delete():
    if 'admin' not in session:
        return redirect("/adminlogin")
    try:
        user_ids = request.form.getlist('user_ids')
        cursor = db.cursor()
        cursor.execute("DELETE FROM users WHERE id IN (%s)" % ','.join(['%s'] * len(user_ids)), tuple(user_ids))
        db.commit()
        admin_logger.info(f"管理员批量删除了用户 ID 为 {user_ids} 的用户信息")
    except Exception as e:
        db.rollback()
        admin_logger.error(f"批量删除用户时出错: {str(e)}")
    return redirect("/admin")

@app.route("/batch_disable", methods=['POST'])
def batch_disable():
    if 'admin' not in session:
        return redirect("/adminlogin")
    try:
        user_ids = request.form.getlist('user_ids')
        cursor = db.cursor()
        cursor.execute("UPDATE users SET is_active=0 WHERE id IN (%s)" % ','.join(['%s'] * len(user_ids)), tuple(user_ids))
        db.commit()
        admin_logger.info(f"管理员批量禁用了用户 ID 为 {user_ids} 的账号")
    except Exception as e:
        db.rollback()
        admin_logger.error(f"批量禁用用户时出错: {str(e)}")
    return redirect("/admin")

@app.route("/toggle_status/<int:user_id>", methods=['POST'])
def toggle_status(user_id):
    if 'admin' not in session:
        return redirect("/adminlogin")
    try:
        cursor = db.cursor()
        cursor.execute("SELECT is_active FROM users WHERE id=%s", (user_id,))
        current_status = cursor.fetchone()[0]
        new_status = 0 if current_status == 1 else 1  # 切换状态
        cursor.execute("UPDATE users SET is_active=%s WHERE id=%s", (new_status, user_id))
        db.commit()
        admin_logger.info(f"管理员将用户 ID 为 {user_id} 的状态切换为 {new_status}")
    except Exception as e:
        db.rollback()
        admin_logger.error(f"切换用户 ID 为 {user_id} 的状态时出错: {str(e)}")
    return redirect("/admin")

def validate_password(password):
    if len(password) < 8 or len(password) > 20:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[$#@]", password):
        return False
    return True

if __name__ == '__main__':
    app.run(debug=True)

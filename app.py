from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
import os
from datetime import timedelta
import secrets
from dotenv import load_dotenv

load_dotenv()  # 本地开发时加载 .env 文件

app = Flask(__name__)

# 从环境变量读取配置
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-only-for-development')

# QQ邮箱配置
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.qq.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', True)
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')  # 你的QQ邮箱
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')  # 你的授权码
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')  # 发件人
# app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] =os.environ.get('DATABASE_URL','sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

# # 邮箱配置
# app.config['MAIL_SERVER'] = 'smtp.gmail.com'
# app.config['MAIL_PORT'] = 587
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')
# app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-app-password')
# app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME', 'your-email@gmail.com')

db = SQLAlchemy(app)
mail = Mail(app)

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(200))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 令牌生成器
def generate_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-verification-salt')

def verify_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-verification-salt', max_age=expiration)
        return email
    except:
        return None

# 发送验证邮件
# def send_verification_email(user_email, token):
#     verification_url = url_for('verify_email', token=token, _external=True)
    
#     msg = Message(
#         subject='验证您的邮箱 - My Blog',
#         recipients=[user_email],
#         html=f'''
#         <h2>欢迎来到 My Blog！</h2>
#         <p>请点击下面的链接完成邮箱验证：</p >
#         <a href=" ">验证我的邮箱</a >
#         <p>如果按钮无法点击，请复制以下链接到浏览器：</p >
#         <p>{verification_url}</p >
#         <p>此验证链接将在1小时后失效。</p >
#         '''
#     )
#     try:
#         mail.send(msg)
#         return True
#     except Exception as e:
#         print(f"邮件发送失败: {e}")
#         return False
def send_verification_email(user_email, token):
    verification_url = url_for('verify_email', token=token, _external=True)
    
    msg = Message(
        subject='【My Blog】邮箱验证 - 请验证您的邮箱地址',
        recipients=[user_email],
        html=f'''
        <div style="font-family: 'Microsoft YaHei', sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #333;">欢迎来到 My Blog！</h2>
            <p>请点击下面的按钮完成邮箱验证：</p >
            <div style="text-align: center; margin: 30px 0;">
                <a href="{verification_url}" 
                   style="background-color: #007bff; color: white; padding: 12px 24px; 
                          text-decoration: none; border-radius: 4px; display: inline-block;">
                   验证我的邮箱
                </a >
            </div>
            <p>如果按钮无法点击，请复制以下链接到浏览器地址栏：</p >
            <p style="word-break: break-all; color: #666; background: #f5f5f5; padding: 10px;">
               {verification_url}
            </p >
            <p><strong>此验证链接将在1小时后失效。</strong></p >
            <hr>
            <p style="color: #999; font-size: 12px;">
               此为系统自动发送邮件，请勿回复。<br>
               如果您没有注册 My Blog，请忽略此邮件。
            </p >
        </div>
        '''
    )
    
    try:
        mail.send(msg)
        print(f"验证邮件已发送至: {user_email}")
        return True
    except Exception as e:
        print(f"邮件发送失败: {e}")
        return False
    
# 登录装饰器
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('请先登录！', 'warning')
            return redirect(url_for('login'))
        
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            flash('用户不存在！', 'error')
            return redirect(url_for('login'))
            
        if not user.is_verified:
            flash('请先验证您的邮箱！', 'warning')
            return redirect(url_for('resend_verification'))
            
        return f(*args, **kwargs)
    return decorated_function

# 简单的CSRF保护
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    return session['csrf_token']

def validate_csrf_token(token):
    return token == session.get('csrf_token')

app.jinja_env.globals['csrf_token'] = generate_csrf_token

# 创建数据库表
with app.app_context():
    db.create_all()

# 路由定义 - 不使用WTForms，直接处理表单
@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and user.is_verified:
            return redirect(url_for('index'))
    
    if request.method == 'POST':
        # 验证CSRF令牌
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('安全验证失败，请重试！', 'error')
            return render_template('login.html')
        
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'
        
        if not username or not password:
            flash('请输入用户名和密码！', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_verified:
                session['temp_user_id'] = user.id
                flash('请先验证您的邮箱！', 'warning')
                return redirect(url_for('resend_verification'))
            
            session['user_id'] = user.id
            session['username'] = user.username
            if remember_me:
                session.permanent = True
            
            flash('登录成功！', 'success')
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误！', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 验证CSRF令牌
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('安全验证失败，请重试！', 'error')
            return render_template('register.html')
        
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not all([username, email, password, confirm_password]):
            flash('请填写所有字段！', 'error')
            return render_template('register.html')
        
        if len(username) < 3:
            flash('用户名至少需要3个字符！', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('密码至少需要6个字符！', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('两次输入的密码不一致！', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(username=username).first():
            flash('用户名已存在！', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('邮箱已被注册！', 'error')
            return render_template('register.html')
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        token = generate_token(email)
        new_user.email_verification_token = token
        # new_user.is_verified = True
        try:
            db.session.add(new_user)
            db.session.commit()
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            flash('注册成功！欢迎使用 My Blog。', 'success')
            # return redirect(url_for('index'))  # 直接跳转到首页
            if send_verification_email(email, token):
                session['temp_user_id'] = new_user.id
                flash('注册成功！请检查您的邮箱并完成验证。', 'success')
                return redirect(url_for('resend_verification'))
            else:
                flash('注册成功，但验证邮件发送失败，请联系管理员。', 'warning')
                return redirect(url_for('resend_verification'))
                
        except Exception as e:
            db.session.rollback()
            flash('注册失败，请稍后重试！', 'error')
            print(f"注册错误: {e}")
    
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    email = verify_token(token)
    if not email:
        flash('验证链接无效或已过期！', 'error')
        return redirect(url_for('resend_verification'))
    
    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        user.is_verified = True
        user.email_verification_token = None
        db.session.commit()
        
        session['user_id'] = user.id
        session['username'] = user.username
        session.pop('temp_user_id', None)
        
        flash('邮箱验证成功！欢迎使用 My Blog。', 'success')
        return redirect(url_for('index'))
    
    flash('验证失败，请重新注册或联系管理员。', 'error')
    return redirect(url_for('register'))

@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        # 验证CSRF令牌
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('安全验证失败，请重试！', 'error')
            return render_template('resend_verification.html', email=session.get('temp_user_email'))
        
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        
        if user and not user.is_verified:
            token = generate_token(email)
            user.email_verification_token = token
            db.session.commit()
            
            if send_verification_email(email, token):
                flash('验证邮件已重新发送，请检查您的邮箱。', 'success')
            else:
                flash('邮件发送失败，请稍后重试。', 'error')
        else:
            flash('邮箱不存在或已验证，请检查输入。', 'error')
    
    user_email = None
    user_id = session.get('temp_user_id')
    if user_id:
        user = User.query.get(user_id)
        if user:
            user_email = user.email
    
    return render_template('resend_verification.html', email=user_email)

@app.route('/logout')
def logout():
    username = session.get('username')
    session.clear()
    if username:
        flash(f'{username}，您已成功退出登录。', 'success')
    else:
        flash('您已成功退出登录。', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
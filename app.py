from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
import os
from datetime import timedelta, datetime, timezone
import secrets
from dotenv import load_dotenv
import resend

load_dotenv()  # 本地开发时加载 .env 文件

app = Flask(__name__)

# 从环境变量读取配置
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-only-for-development')

# 配置 Resend
resend.api_key = os.environ.get('RESEND_API_KEY')

database_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
# 修复 PostgreSQL 连接字符串格式
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

db = SQLAlchemy(app)

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 未验证用户临时存储模型
class PendingUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    verification_token = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

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

# 使用 Resend 发送验证邮件
def send_verification_email(user_email, token):
    verification_url = url_for('verify_email', token=token, _external=True)
    from_email = os.environ.get('FROM_EMAIL', 'onboarding@resend.dev')
    
    html_content = f'''
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
    
    try:
        print(f"尝试发送邮件到: {user_email}")
        print(f"使用发件人: {from_email}")
        print(f"Resend API Key 存在: {bool(os.environ.get('RESEND_API_KEY'))}")
        
        r = resend.Emails.send({
            'from': f'My Blog <{from_email}>',
            'to': [user_email],
            'subject': '【My Blog】邮箱验证 - 请验证您的邮箱地址',
            'html': html_content
        })
        print(f"验证邮件已发送至: {user_email}")
        print(f"Resend 响应: {r}")
        return True
    except Exception as e:
        print(f"Resend 邮件发送失败: {e}")
        import traceback
        traceback.print_exc()  # 打印完整的错误堆栈
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

# 路由定义
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
                flash('请先验证您的邮箱！您可以通过"重新发送验证邮件"功能完成验证。', 'warning')
                # 自动填充邮箱到重新发送验证页面
                session['temp_user_email'] = user.email
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
        
        # 检查用户名和邮箱是否已被使用（包括已验证和未验证的用户）
        if User.query.filter_by(username=username).first() or PendingUser.query.filter_by(username=username).first():
            flash('用户名已存在！', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first() or PendingUser.query.filter_by(email=email).first():
            flash('邮箱已被注册！', 'error')
            return render_template('register.html')
        
        # 创建PendingUser而不是直接创建User
        token = generate_token(email)
        pending_user = PendingUser(
            username=username,
            email=email,
            verification_token=token
        )
        pending_user.set_password(password)
        
        try:
            db.session.add(pending_user)
            db.session.commit()
            
            if send_verification_email(email, token):
                session['pending_user_id'] = pending_user.id
                flash('注册成功！请检查您的邮箱并完成验证。', 'success')
                return redirect(url_for('resend_verification'))
            else:
                # 如果邮件发送失败，删除PendingUser记录
                db.session.delete(pending_user)
                db.session.commit()
                flash('验证邮件发送失败，请稍后重试。', 'error')
                return render_template('register.html')
                
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
    
    # 首先查找PendingUser记录
    pending_user = PendingUser.query.filter_by(email=email, verification_token=token).first()
    if pending_user:
        # 创建真正的用户记录
        user = User(
            username=pending_user.username,
            email=pending_user.email,
            password_hash=pending_user.password_hash,
            is_verified=True
        )
        
        try:
            db.session.add(user)
            # 删除PendingUser记录
            db.session.delete(pending_user)
            db.session.commit()
            
            session['user_id'] = user.id
            session['username'] = user.username
            session.pop('pending_user_id', None)
            
            flash('邮箱验证成功！欢迎使用 My Blog。', 'success')
            return redirect(url_for('index'))
        
        except Exception as e:
            db.session.rollback()
            flash('验证失败，请重新注册！', 'error')
            print(f"验证错误: {e}")
            return redirect(url_for('register'))
    
    # 如果不是PendingUser，检查是否是现有User
    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        # 验证现有用户
        user.is_verified = True
        db.session.commit()
        
        session['user_id'] = user.id
        session['username'] = user.username
        
        flash('邮箱验证成功！欢迎使用 My Blog。', 'success')
        return redirect(url_for('index'))
    
    flash('验证失败，请重新注册或联系管理员。', 'error')
    return redirect(url_for('register'))

@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token')):
            flash('安全验证失败，请重试！', 'error')
            return render_template('resend_verification.html')
        
        email = request.form.get('email', '').strip().lower()
        
        # 首先查找PendingUser记录
        pending_user = PendingUser.query.filter_by(email=email).first()
        if pending_user:
            # 生成新的令牌
            token = generate_token(email)
            pending_user.verification_token = token
            db.session.commit()
            
            if send_verification_email(email, token):
                session['pending_user_id'] = pending_user.id
                flash('验证邮件已重新发送，请检查您的邮箱。', 'success')
            else:
                flash('邮件发送失败，请稍后重试。', 'error')
        else:
            # 检查是否是现有的未验证User
            user = User.query.filter_by(email=email).first()
            if user:
                if user.is_verified:
                    flash('该邮箱已验证，请直接登录！', 'info')
                    return redirect(url_for('login'))
                else:
                    # 为现有未验证用户生成令牌并发送邮件
                    token = generate_token(email)
                    # 临时存储令牌在session中
                    session['temp_verification_token'] = token
                    session['temp_verification_email'] = email
                    
                    if send_verification_email(email, token):
                        flash('验证邮件已发送，请检查您的邮箱。', 'success')
                    else:
                        flash('邮件发送失败，请稍后重试。', 'error')
            else:
                flash('邮箱不存在，请先注册。', 'error')
                return redirect(url_for('register'))
    
    # 显示页面时，如果有pending_user_id，自动填充邮箱
    email = None
    pending_user_id = session.get('pending_user_id')
    if pending_user_id:
        pending_user = PendingUser.query.get(pending_user_id)
        if pending_user:
            email = pending_user.email
    
    # 如果有临时存储的邮箱，也显示
    if not email and session.get('temp_user_email'):
        email = session.get('temp_user_email')
    
    return render_template('resend_verification.html', email=email)

@app.route('/logout')
def logout():
    username = session.get('username')
    session.clear()
    if username:
        flash(f'{username}，您已成功退出登录。', 'success')
    else:
        flash('您已成功退出登录。', 'success')
    return redirect(url_for('login'))

# 清理过期PendingUser的定时任务（可选）
def cleanup_expired_pending_users():
    """清理超过24小时的未验证用户"""
    expiration_time = datetime.now(timezone.utc) - timedelta(hours=24)
    expired_users = PendingUser.query.filter(PendingUser.created_at < expiration_time).all()
    for user in expired_users:
        db.session.delete(user)
    db.session.commit()
    print(f"清理了 {len(expired_users)} 个过期待验证用户")

if __name__ == '__main__':
    # 每次启动时清理过期PendingUser
    with app.app_context():
        cleanup_expired_pending_users()
    app.run(host='0.0.0.0', port=5000, debug=False)
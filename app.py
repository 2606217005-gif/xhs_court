from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import re
import random
import string
import os
import uuid
import json
import requests
import base64
from sqlalchemy import text, inspect
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import socket
import traceback

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')

# --- Supabase/DB URL 解析与自动修正 ---
def _normalize_supabase_db_url(raw_url: str | None):
    """规范协议前缀（postgres:// -> postgresql://），并清理未知查询参数。
    返回 (url, meta)。meta 如 {"rewritten": False, "query_cleaned": True, "dropped_params": [..]}。
    """
    meta = {"rewritten": False}
    if not raw_url:
        return None, meta
    url = raw_url
    try:
        if url.startswith('postgres://'):
            url = 'postgresql://' + url[len('postgres://'):]
        # 清理未知查询参数，避免 psycopg2/libpq 报 invalid dsn
        u = urlparse(url)
        if u.query:
            pairs = parse_qsl(u.query, keep_blank_values=True)
            allowed = {
                'sslmode',
                'application_name',
                'connect_timeout',
                # 常见兼容键，必要时可扩展
            }
            kept = []
            dropped = []
            for k, v in pairs:
                if k in allowed:
                    kept.append((k, v))
                else:
                    dropped.append(k)
            if dropped:
                new_query = urlencode(kept)
                url = urlunparse((u.scheme, u.netloc, u.path, u.params, new_query, u.fragment))
                meta.update({'query_cleaned': True, 'dropped_params': dropped})

        # 校验主机名：若缺失或仅由点组成（例如 "..."），视为无效并回退
        u_final = urlparse(url)
        host = u_final.hostname
        if not host or set(host) <= {'.'}:
            meta.update({'invalid_host': True, 'raw_host': host})
            return None, meta
    except Exception as _e:
        meta.update({'error': str(_e)})
    return url, meta

# 数据库配置：优先使用直连 Postgres（POSTGRES_URL_NON_POOLING），否则尝试自动修正 Supabase Pooler，再回退到 /tmp SQLite
_db_url_source = None
_db_url_meta = {}
_db_url = None
# 优先使用自动生成的 POSTGRES_URL (Supabase Pooler, IPv4)，其次 DATABASE_URL，再尝试直连与 Prisma URL
for env_name in ['POSTGRES_URL', 'DATABASE_URL', 'POSTGRES_URL_NON_POOLING', 'POSTGRES_PRISMA_URL']:
    _raw = os.getenv(env_name)
    if _raw:
        _db_url_source = env_name
        _db_url, _db_url_meta = _normalize_supabase_db_url(_raw)
        break

if _db_url:
    app.config['SQLALCHEMY_DATABASE_URI'] = _db_url
else:
    # 在 Vercel 等无状态平台使用 /tmp 临时数据库，避免写入只读目录
    tmp_db_path = os.getenv('SERVERLESS_TMP_DB', '/tmp/xiaohongshu_court.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{tmp_db_path}'
    _db_url_source = 'sqlite_tmp'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 豆包模型API配置（支持环境变量覆盖，提供安全fallback）
DOUBAO_API_URL = os.getenv('DOUBAO_API_URL', 'https://ark.cn-beijing.volces.com/api/v3/chat/completions')
DOUBAO_API_KEY = os.getenv('DOUBAO_API_KEY', '5a90add4-8311-45fd-afa7-2149021f1528')
DOUBAO_MODEL = os.getenv('DOUBAO_MODEL', 'doubao-seed-1-6-251015')
# 为避免超长响应导致页面卡顿，这里做一个上限保护
DOUBAO_MAX_COMPLETION_TOKENS = int(os.getenv('DOUBAO_MAX_COMPLETION_TOKENS', '65535'))
DOUBAO_SAFE_MAX_COMPLETION_TOKENS = min(DOUBAO_MAX_COMPLETION_TOKENS, 4096)

# 文件上传配置（在 Serverless 环境使用 /tmp 以避免只读文件系统问题）
_serverless_tmp_root = '/tmp'
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', os.path.join(_serverless_tmp_root, 'uploads'))
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB

# 尝试创建上传目录（在只读环境会失败，Supabase 存储路径会作为首选）
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
except Exception as e:
    print('Init uploads dir failed:', e)

# 允许的文件类型
ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'gif', 'webp'},
    'audio': {'mp3', 'wav', 'ogg', 'm4a'},
    'video': {'mp4', 'avi', 'mov', 'wmv'},
    'file': {'pdf', 'doc', 'docx', 'txt', 'xlsx', 'pptx'}
}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# 启动时尝试创建缺失的数据库表（对任何数据库均安全，create_all 仅创建不存在的表）
try:
    with app.app_context():
        db.create_all()
except Exception as e:
    # 不中断启动，记录错误以便诊断（Postgres/Supabase 连接失败或权限不足时可能触发）
    print('DB init create_all failed:', e)

# Supabase 存储与数据库（用于云端部署）
SUPABASE_URL = os.getenv('SUPABASE_URL') or os.getenv('NEXT_PUBLIC_SUPABASE_URL')
SUPABASE_SERVICE_ROLE_KEY = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
SUPABASE_ANON_KEY = os.getenv('SUPABASE_ANON_KEY') or os.getenv('NEXT_PUBLIC_SUPABASE_ANON_KEY')
SUPABASE_BUCKET = os.getenv('SUPABASE_BUCKET', 'evidences')
_supabase_client = None
_supabase_client_kind = None  # 'service' or 'anon'

# 惰性初始化 Supabase 客户端，避免导入期网络调用导致冷启动失败
def get_supabase_client():
    global _supabase_client
    global _supabase_client_kind
    if _supabase_client:
        return _supabase_client
    if not SUPABASE_URL:
        return None
    try:
        from supabase import create_client
        # 优先使用 service role key；没有则尝试 anon key（可能受 RLS 限制，无法创建桶）
        if SUPABASE_SERVICE_ROLE_KEY:
            _supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
            _supabase_client_kind = 'service'
        elif SUPABASE_ANON_KEY:
            _supabase_client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
            _supabase_client_kind = 'anon'
        else:
            _supabase_client = None
            _supabase_client_kind = None
            return None
        return _supabase_client
    except Exception as e:
        print('Supabase client init failed:', e)
        _supabase_client = None
        _supabase_client_kind = None
        return None

# 在运行时确保桶存在；失败时仅记录日志并回退到本地存储
def ensure_supabase_bucket(client, bucket_name: str) -> bool:
    if not client:
        return False
    # 先用 list_buckets 判断是否已存在（不同版本返回结构可能不同）
    try:
        buckets = client.storage.list_buckets()
        def _bucket_name(b):
            try:
                return getattr(b, 'name', getattr(b, 'id', None)) or (b.get('name') if isinstance(b, dict) else None) or (b.get('id') if isinstance(b, dict) else None)
            except Exception:
                return None
        names = [n for n in (_bucket_name(b) for b in buckets) if n]
        if bucket_name in names:
            return True
    except Exception as e:
        # 列举失败不应阻断后续创建
        print('Supabase list_buckets failed:', e)

    # 创建桶（位置参数以兼容 supabase-py v2 同步 API）
    try:
        client.storage.create_bucket(bucket_name)
        # 尝试设置为 public（不同版本可能不支持该签名，失败不阻断）
        try:
            client.storage.update_bucket(bucket_name, public=True)
        except Exception as e:
            print('Supabase update_bucket(public=True) failed:', repr(e))
        return True
    except Exception as e:
        msg = str(e)
        # 若报已存在或冲突，视为成功（不同版本可能返回 409 或特定文案）
        if ('exists' in msg.lower()) or ('already' in msg.lower()) or ('409' in msg):
            return True
        print('Supabase ensure_bucket failed:', repr(e))
        return False

# 数据模型定义
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Case(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    case_type = db.Column(db.String(20), nullable=False)  # civil, general
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, ongoing, settled, closed
    initiator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    opponent_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    initiator = db.relationship('User', foreign_keys=[initiator_id], backref='initiated_cases')
    opponent = db.relationship('User', foreign_keys=[opponent_id], backref='opposed_cases')

class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    submitter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=True)  # 文本描述
    file_path = db.Column(db.String(255), nullable=True)  # 文件路径
    evidence_type = db.Column(db.String(50), nullable=False, default='text')  # text, image, audio, video, file
    file_type = db.Column(db.String(50), nullable=True)  # 具体文件类型
    is_key = db.Column(db.Boolean, default=False)
    is_proxy = db.Column(db.Boolean, default=False)
    likes = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), nullable=True)  # complete, incomplete
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    case = db.relationship('Case', backref='evidences')
    submitter = db.relationship('User', backref='evidences')

class EvidenceLegalNote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    legal_article = db.Column(db.String(200), nullable=False)
    note_content = db.Column(db.Text, nullable=False)
    
    evidence = db.relationship('Evidence', backref='legal_notes')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    processed_content = db.Column(db.Text, nullable=True)  # 处理后的内容
    violation_reason = db.Column(db.String(200), nullable=True)  # 违规原因
    likes = db.Column(db.Integer, default=0)
    is_blocked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    case = db.relationship('Case', backref='comments')
    author = db.relationship('User', backref='comments')

class TimelineEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    case = db.relationship('Case', backref='timeline')

class MediationAgreement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    initiator_signed = db.Column(db.Boolean, default=False)
    opponent_signed = db.Column(db.Boolean, default=False)
    initiator_confirmed = db.Column(db.Boolean, default=False)  # 发起方确认案件事实
    opponent_confirmed = db.Column(db.Boolean, default=False)  # 对峙方确认案件事实
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    facts_summary = db.Column(db.Text, nullable=True)  # AI生成的案件事实摘要
    
    case = db.relationship('Case', backref='mediation_agreement')

# 电子签名记录
class Signature(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    agreement_id = db.Column(db.Integer, db.ForeignKey('mediation_agreement.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_path = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    agreement = db.relationship('MediationAgreement', backref='signatures')
    user = db.relationship('User')

class Support(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    side = db.Column(db.String(20), nullable=False)  # initiator, opponent
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='supports')
    case = db.relationship('Case', backref='supports')

class EvidenceLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='evidence_likes')
    evidence = db.relationship('Evidence', backref='evidence_likes')

class CommentLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    user = db.relationship('User', backref='comment_likes')
    comment = db.relationship('Comment', backref='comment_likes')

# 敏感词模型：按类别与级别分级
class SensitiveWord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    word = db.Column(db.String(100), unique=True, nullable=False)
    category = db.Column(db.String(50), nullable=False)  # insult, discrimination, hate, profanity
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# 管理员校验（环境变量 ADMIN_USERNAMES，逗号分隔）
ADMIN_USERNAMES = [u.strip() for u in os.getenv('ADMIN_USERNAMES', 'admin').split(',') if u.strip()]

def admin_required(view_func):
    from functools import wraps
    @wraps(view_func)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or current_user.username not in ADMIN_USERNAMES:
            flash('需要管理员权限', 'error')
            return redirect(url_for('index'))
        return view_func(*args, **kwargs)
    return wrapper


# 健康检查与诊断辅助函数与路由
def _path_writeable(path: str):
    try:
        os.makedirs(path, exist_ok=True)
        test_file = os.path.join(path, f".__rw_test_{uuid.uuid4().hex}")
        with open(test_file, 'w') as f:
            f.write('ok')
        os.remove(test_file)
        return True, 'ok'
    except Exception as e:
        return False, str(e)


def _db_ping():
    try:
        with app.app_context():
            # 使用 SQLAlchemy 2.0 的 text 进行简单查询
            db.session.execute(text('SELECT 1'))
        return True, 'ok'
    except Exception as e:
        return False, str(e)


def _redact_db_uri(uri: str | None):
    if not uri:
        return 'sqlite:///tmp'
    try:
        # 简单脱敏：隐藏凭据部分
        if '://' in uri and '@' in uri:
            scheme, rest = uri.split('://', 1)
            creds_host = rest.split('@', 1)
            if len(creds_host) == 2:
                _, hostpart = creds_host
                return f"{scheme}://***:***@{hostpart}"
        return uri
    except Exception:
        return 'unknown'


@app.route('/__health')
def __health():
    db_ok, db_msg = _db_ping()
    tmp_ok, tmp_msg = _path_writeable('/tmp')
    uploads_ok, uploads_msg = _path_writeable(app.config.get('UPLOAD_FOLDER', '/tmp/uploads'))

    supabase_env_ok = bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)
    status = 'ok' if (db_ok and tmp_ok and uploads_ok) else 'degraded'
    return jsonify({
        'status': status,
        'db': {'ok': db_ok, 'msg': db_msg},
        'tmp': {'ok': tmp_ok, 'msg': tmp_msg},
        'uploads': {'ok': uploads_ok, 'msg': uploads_msg},
        'supabase_env': {'configured': supabase_env_ok},
    }), 200


@app.route('/__diag')
def __diag():
    db_ok, db_msg = _db_ping()
    tmp_ok, tmp_msg = _path_writeable('/tmp')
    uploads_ok, uploads_msg = _path_writeable(app.config.get('UPLOAD_FOLDER', '/tmp/uploads'))

    py_ver = f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}"
    from flask import __version__ as flask_version

    diag = {
        'db': {
            'ok': db_ok,
            'msg': db_msg,
            'uri_redacted': _redact_db_uri(os.getenv('DATABASE_URL')),
            'sqlalchemy_uri_redacted': _redact_db_uri(app.config.get('SQLALCHEMY_DATABASE_URI')),
            'using_tmp_sqlite': not _db_url,
            'source': _db_url_source,
            'normalized': _db_url_meta,
            'env_present': {
                'POSTGRES_URL': bool(os.getenv('POSTGRES_URL')),
                'DATABASE_URL': bool(os.getenv('DATABASE_URL')),
                'POSTGRES_URL_NON_POOLING': bool(os.getenv('POSTGRES_URL_NON_POOLING')),
                'POSTGRES_PRISMA_URL': bool(os.getenv('POSTGRES_PRISMA_URL')),
            }
        },
        'paths': {
            'tmp_rw': {'ok': tmp_ok, 'msg': tmp_msg},
            'uploads_rw': {'ok': uploads_ok, 'msg': uploads_msg},
            'uploads_folder': app.config.get('UPLOAD_FOLDER'),
        },
        'supabase': {
            'configured': bool(SUPABASE_URL and (SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY)),
            'bucket': SUPABASE_BUCKET,
            'env': {
                'url': bool(SUPABASE_URL),
                'service_key': bool(SUPABASE_SERVICE_ROLE_KEY),
                'anon_key': bool(SUPABASE_ANON_KEY),
                'key_kind': _supabase_client_kind,
            }
        },
        'runtime': {
            'python': py_ver,
            'flask': flask_version,
            'debug': app.debug,
        }
    }
    return jsonify(diag), 200

def _safe_startup_migrations():
    """在启动时执行安全迁移，添加缺失的列以避免运行时报错。
    仅用于轻量开发环境，生产环境推荐使用标准迁移机制。
    """
    try:
        insp = inspect(db.engine)
        cols = {c['name'] for c in insp.get_columns('comment')}
        pending_sql = []
        if 'processed_content' not in cols:
            pending_sql.append('ALTER TABLE comment ADD COLUMN processed_content TEXT;')
        if 'violation_reason' not in cols:
            pending_sql.append('ALTER TABLE comment ADD COLUMN violation_reason VARCHAR(200);')
        for sql in pending_sql:
            try:
                db.session.execute(text(sql))
            except Exception:
                pass
        if pending_sql:
            db.session.commit()
    except Exception:
        # 避免启动失败
        pass

# 测试页面渲染
@app.route('/test_supabase')
def test_supabase():
    return render_template('test_supabase.html')

# 测试：数据库 ping
@app.route('/api/test/db_ping')
def api_test_db_ping():
    ok, msg = _db_ping()
    return jsonify({'ok': ok, 'msg': msg}), (200 if ok else 500)

# 测试：Supabase ping 与桶可用性
@app.route('/api/test/supabase_ping')
def api_test_supabase_ping():
    client = get_supabase_client()
    from datetime import datetime
    res = {
        'configured': bool(SUPABASE_URL and (SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ANON_KEY)),
        'client_created': bool(client),
        'bucket': SUPABASE_BUCKET,
        'ok': False,
        'diagnostic_version': 2,
        'server_time': datetime.utcnow().isoformat() + 'Z',
        # 默认字段占位，保证前端总能看到完整结构
        'can_list_buckets': False,
        'buckets': [],
        'bucket_exists': False,
        'bucket_created': False,
        'create_error': None,
        'create_error_repr': None,
    }
    res['env'] = {
        'url': bool(SUPABASE_URL),
        'service_key': bool(SUPABASE_SERVICE_ROLE_KEY),
        'anon_key': bool(SUPABASE_ANON_KEY),
        'key_kind': _supabase_client_kind,
    }
    if not client:
        res['error'] = 'client_init_failed'
        return jsonify(res), 200
    # 列出桶，帮助诊断权限/网络问题，并用其判断存在性
    try:
        buckets = client.storage.list_buckets()
        # 将返回对象序列化为名字列表（不同版本返回结构可能不同）
        names = []
        for b in buckets:
            name = None
            try:
                name = getattr(b, 'name', None)
            except Exception:
                name = None
            if not name:
                try:
                    name = getattr(b, 'id', None)
                except Exception:
                    name = None
            if not name and isinstance(b, dict):
                name = b.get('name') or b.get('id')
            names.append(name or str(b))
        res['buckets'] = names
        res['can_list_buckets'] = True
        res['bucket_exists'] = SUPABASE_BUCKET in res.get('buckets', [])
    except Exception as e:
        res['can_list_buckets'] = False
        res['list_error'] = str(e)
        res['bucket_exists'] = False

    # 若不存在则尝试创建
    try:
        if not res.get('bucket_exists'):
            try:
                client.storage.create_bucket(SUPABASE_BUCKET)
                # 设置为 public（若不支持该签名则忽略错误并记录）
                try:
                    client.storage.update_bucket(SUPABASE_BUCKET, public=True)
                except Exception as ue:
                    res['update_error'] = str(ue)
                    res['update_error_repr'] = repr(ue)
                res['bucket_created'] = True
                # 再次列举以确认
                try:
                    buckets2 = client.storage.list_buckets()
                    names2 = []
                    for b in buckets2:
                        n2 = None
                        try:
                            n2 = getattr(b, 'name', None)
                        except Exception:
                            n2 = None
                        if not n2:
                            try:
                                n2 = getattr(b, 'id', None)
                            except Exception:
                                n2 = None
                        if not n2 and isinstance(b, dict):
                            n2 = b.get('name') or b.get('id')
                        names2.append(n2 or str(b))
                    res['bucket_exists'] = SUPABASE_BUCKET in names2
                except Exception:
                    res['bucket_exists'] = True  # 创建成功但列举失败，暂视为存在
            except Exception as e:
                msg = str(e)
                res['bucket_created'] = False
                res['create_error'] = msg
                res['create_error_repr'] = repr(e)
                # 若冲突/已存在，视为存在
                if ('exists' in msg.lower()) or ('already' in msg.lower()) or ('409' in msg):
                    res['bucket_exists'] = True
        # 最终判定
        res['ok'] = bool(res.get('bucket_exists'))
        return jsonify(res), 200
    except Exception as e:
        res['error'] = str(e)
        return jsonify(res), 500

# 测试：文件上传（优先 Supabase，回退本地）
@app.route('/api/test/upload', methods=['POST'])
def api_test_upload():
    if 'file' not in request.files or request.files['file'].filename == '':
        return jsonify({'ok': False, 'error': 'missing file'}), 400
    file = request.files['file']
    filename = generate_unique_filename(file.filename)

    client = get_supabase_client()
    if client:
        try:
            ensure_supabase_bucket(client, SUPABASE_BUCKET)
            cloud_path = f"test/{filename}"
            file_bytes = file.read()
            client.storage.from_(SUPABASE_BUCKET).upload(cloud_path, file_bytes, file_options={"contentType": file.mimetype})
            public_url = client.storage.from_(SUPABASE_BUCKET).get_public_url(cloud_path)
            return jsonify({'ok': True, 'storage': 'supabase', 'url': public_url, 'path': cloud_path}), 200
        except Exception as e:
            # 回退到本地，但携带出错信息
            supabase_error = str(e)
    else:
        supabase_error = 'client_init_failed'

    case_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'test')
    os.makedirs(case_folder, exist_ok=True)
    try:
        file.stream.seek(0)
    except Exception:
        pass
    local_path = os.path.join(case_folder, filename)
    file.save(local_path)
    return jsonify({'ok': True, 'storage': 'local', 'url': url_for('uploaded_file', filename=f"test/{filename}"), 'path': f"test/{filename}", 'supabase_error': supabase_error}), 200

# 测试：查询案件证据列表
@app.route('/api/test/evidences/<int:case_id>')
def api_test_evidences(case_id):
    # 增强健壮性：带诊断信息与错误处理，避免直接500
    try:
        # 基本诊断：DB ping 与 URI脱敏
        ok_ping, msg_ping = _db_ping()
        diag = {
            'db_ping': {'ok': ok_ping, 'msg': msg_ping},
            'db_uri': _redact_db_uri(app.config.get('SQLALCHEMY_DATABASE_URI')),
        }

        # 查询列表
        rows = db.session.query(Evidence).filter_by(case_id=case_id).order_by(Evidence.created_at.desc()).all()

        items = []
        for e in rows:
            # 防御式格式化 created_at
            try:
                created_str = e.created_at.isoformat() if getattr(e, 'created_at', None) else None
            except Exception:
                created_str = str(getattr(e, 'created_at', None)) if getattr(e, 'created_at', None) else None

            items.append({
                'id': e.id,
                'type': e.evidence_type,
                'file_path': e.file_path,
                'file_type': e.file_type,
                'content': e.content,
                'is_key': e.is_key,
                'is_proxy': e.is_proxy,
                'submitter_id': e.submitter_id,
                'created_at': created_str,
            })

        return jsonify({'ok': True, 'count': len(items), 'items': items, 'diag': diag}), 200
    except Exception as e:
        import traceback as _tb
        return jsonify({
            'ok': False,
            'error': str(e),
            'trace': _tb.format_exc(),
        }), 200

@app.route('/api/test/ai_moderation', methods=['POST'])
def api_test_ai_moderation():
    """测试用API：AI内容审核"""
    data = request.get_json()
    content = data.get('content', '')
    
    if not content:
        return jsonify({'error': '缺少内容参数'}), 400
    
    result = ai_content_moderation(content)
    return jsonify(result)

@app.route('/api/test/ai_privacy', methods=['POST'])
def api_test_ai_privacy():
    """测试用API：AI隐私信息识别"""
    data = request.get_json()
    content = data.get('content', '')
    
    if not content:
        return jsonify({'error': '缺少内容参数'}), 400
    
    result = ai_privacy_detection(content)
    return jsonify(result)

@app.route('/api/test/intelligent_pipeline', methods=['POST'])
def api_test_intelligent_pipeline():
    """测试用API：智能内容预处理管道"""
    data = request.get_json()
    content = data.get('content', '')
    enable_privacy_masking = data.get('enable_privacy_masking', True)
    
    if not content:
        return jsonify({'error': '缺少内容参数'}), 400
    
    result = intelligent_content_pipeline(content, enable_privacy_masking)
    return jsonify(result)

# 文本规范化：半角化、lower、去空白与标点
def _to_halfwidth(s: str) -> str:
    result = []
    for ch in s:
        code = ord(ch)
        if code == 12288:  # 全角空格
            result.append(' ')
        elif 65281 <= code <= 65374:  # 全角字符范围
            result.append(chr(code - 65248))
        else:
            result.append(ch)
    return ''.join(result)

def normalize_text(content: str) -> str:
    if not content:
        return ''
    normalized = _to_halfwidth(content).lower()
    normalized = re.sub(r"[\s\W_]+", "", normalized)
    return normalized

# 辅助函数
def allowed_file(filename, file_type):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS.get(file_type, set())

def get_file_type(filename):
    ext = filename.rsplit('.', 1)[1].lower()
    for file_type, extensions in ALLOWED_EXTENSIONS.items():
        if ext in extensions:
            return file_type
    return 'file'

def generate_unique_filename(filename):
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    unique_id = str(uuid.uuid4())
    return f"{unique_id}.{ext}" if ext else unique_id

# 豆包API客户端
def doubao_chat(messages, temperature=0.2, top_p=0.9):
    try:
        payload = {
            "model": DOUBAO_MODEL,
            "messages": messages,
            "max_completion_tokens": DOUBAO_SAFE_MAX_COMPLETION_TOKENS,
            "temperature": temperature,
            "top_p": top_p,
        }
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {DOUBAO_API_KEY}",
        }
        resp = requests.post(DOUBAO_API_URL, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # 兼容不同返回结构
        if isinstance(data, dict):
            # OpenAI风格
            choices = data.get("choices")
            if choices and isinstance(choices, list):
                message = choices[0].get("message") if choices else None
                if message and isinstance(message, dict):
                    content = message.get("content")
                    if content:
                        return content
            # 其他可能字段
            if "output_text" in data:
                return data["output_text"]
        return None
    except requests.RequestException as e:
        # 记录错误但不抛出，返回None由上层回退
        print(f"[Doubao API Error] {e}")
        try:
            # 打印更多响应信息
            if e.response is not None:
                print(f"[Doubao API Response] {e.response.status_code} {e.response.text}")
        except Exception:
            pass
        return None

# AI函数：智能隐私信息识别与抹除
def process_privacy_removal(content):
    """
    使用豆包API进行智能隐私信息识别和抹除
    如果AI处理失败，回退到传统正则表达式处理
    """
    if not content or not content.strip():
        return content
    
    # 首先尝试AI智能隐私识别
    ai_result = ai_privacy_detection(content)
    if ai_result and ai_result.get('sanitized_content'):
        return ai_result['sanitized_content']
    
    # AI处理失败时回退到传统正则表达式处理
    return fallback_privacy_processing(content)

def ai_privacy_detection(content):
    """
    使用豆包API进行智能隐私信息识别
    返回: {'has_privacy': bool, 'privacy_items': list, 'sanitized_content': str}
    """
    if not content or not content.strip():
        return {'has_privacy': False, 'privacy_items': [], 'sanitized_content': content}
    
    try:
        messages = [
            {"role": "system", "content": """
            你是一个隐私信息识别专家，能够准确识别文本中的各种隐私信息。
            
            请识别以下文本中的隐私信息，包括：
            - 手机号、电话号码
            - 邮箱地址
            - 身份证号、护照号
            - 银行卡号、支付账号
            - 家庭住址、具体地址
            - 真实姓名
            - 公司名称、组织名称
            - 其他可能识别个人身份的信息
            
            返回JSON格式：
            {
                "has_privacy": boolean,      // 是否包含隐私信息
                "privacy_items": [          // 隐私信息列表
                    {
                        "type": string,     // 隐私类型
                        "content": string,  // 原始内容
                        "position": [start, end]  // 位置信息
                    }
                ],
                "sanitized_content": string  // 脱敏后的内容
            }
            
            脱敏规则：
            - 手机号：保留前3位和后4位，中间用****代替
            - 邮箱：保留@符号前后各一个字符，其他用*代替
            - 身份证号：保留前6位和后4位，中间用********代替
            - 地址：保留省市信息，具体地址用***代替
            - 姓名：保留姓氏，名字用*代替
            - 公司/组织名称：用[公司A]、[组织B]等匿名化标识
            
            请基于语义理解进行识别，不要仅依赖正则表达式。
            """},
            {"role": "user", "content": f"请识别并脱敏以下内容：\n{content}"}
        ]
        
        result = doubao_chat(messages, temperature=0.1)
        if result:
            try:
                parsed = json.loads(result)
                if isinstance(parsed, dict) and 'has_privacy' in parsed:
                    return parsed
            except json.JSONDecodeError:
                pass
        
        # 回退到传统隐私处理
        return fallback_privacy_processing(content)
        
    except Exception as e:
        print(f"[AI Privacy Detection Error] {e}")
        return fallback_privacy_processing(content)

def fallback_privacy_processing(content):
    """传统隐私处理回退方案"""
    # 替换手机号
    content = re.sub(r'1[3-9]\d{9}', '[手机号已抹除]', content)
    # 替换邮箱
    content = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[邮箱已抹除]', content)
    # 替换身份证号
    content = re.sub(r'[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]', '[身份证号已抹除]', content)
    # 替换地址（简单处理）
    address_patterns = ['小区', '街道', '路', '巷', '弄', '村', '栋', '号', '室']
    for pattern in address_patterns:
        if pattern in content:
            # 简单处理，实际应该更复杂
            pass
    
    return {'has_privacy': True, 'privacy_items': [], 'sanitized_content': content}

def intelligent_content_pipeline(content, enable_privacy_masking=True):
    """
    智能内容预处理管道
    整合AI内容审核和隐私信息识别功能
    
    参数:
    - content: 待处理的文本内容
    - enable_privacy_masking: 是否启用隐私信息脱敏
    
    返回:
    {
        'processed_content': str,      # 处理后的内容
        'is_allowed': bool,              # 是否通过审核
        'violation_info': dict,        # 违规信息（如果有）
        'privacy_info': dict,            # 隐私信息处理结果
        'processing_log': list,          # 处理日志
        'sensitive_words_info': dict     # 敏感词处理信息
    }
    """
    processing_log = []
    result = {
        'processed_content': content,
        'is_allowed': True,
        'violation_info': None,
        'privacy_info': None,
        'processing_log': processing_log,
        'sensitive_words_info': None
    }
    
    if not content or not content.strip():
        processing_log.append("内容为空，跳过处理")
        return result
    
    original_content = content
    processing_log.append("开始智能内容预处理")
    
    # 第一步：敏感词局部替换（新策略）
    processing_log.append("执行敏感词局部替换...")
    sensitive_result = replace_sensitive_words(content, replacement='****')
    
    if sensitive_result['has_sensitive_words']:
        content = sensitive_result['processed_content']
        processing_log.append(f"替换了 {sensitive_result['replacement_count']} 个敏感词: {', '.join(sensitive_result['replaced_words'])}")
        
        result['sensitive_words_info'] = {
            'has_replacements': True,
            'replaced_words': sensitive_result['replaced_words'],
            'replacement_count': sensitive_result['replacement_count']
        }
        
        # 只有严重违规词才标记为不允许
        # 这里我们采用更宽松的策略，允许替换后的内容发布
        processing_log.append("敏感词已替换，内容允许发布")
    else:
        processing_log.append("未发现敏感词")
        result['sensitive_words_info'] = {
            'has_replacements': False,
            'replaced_words': [],
            'replacement_count': 0
        }
    
    # 第二步：AI内容审核（用于检测严重违规，可能需要整体屏蔽）
    processing_log.append("执行AI内容审核...")
    moderation_result = ai_content_moderation(content)
    
    if moderation_result.get('is_violation'):
        severity = moderation_result.get('severity', 'unknown')
        reason = moderation_result.get('reason', '未知原因')
        
        # 只有严重违规才整体屏蔽
        if severity == 'high':
            processing_log.append(f"内容包含严重违规信息 - 严重程度: {severity}, 原因: {reason}")
            
            result['is_allowed'] = False
            result['violation_info'] = {
                'severity': severity,
                'reason': reason,
                'suggestion': '请修改内容后重新提交'
            }
            return result
        else:
            processing_log.append(f"内容包含中等违规信息，但已替换敏感词，允许发布 - 原因: {reason}")
    else:
        processing_log.append("AI内容审核通过")
    
    # 第三步：隐私信息识别与脱敏（如果启用）
    if enable_privacy_masking:
        processing_log.append("执行隐私信息识别与脱敏...")
        privacy_result = ai_privacy_detection(content)
        
        if privacy_result and privacy_result.get('has_privacy'):
            content = privacy_result.get('sanitized_content', content)
            privacy_items = privacy_result.get('privacy_items', [])
            
            processing_log.append(f"发现并脱敏了 {len(privacy_items)} 个隐私信息")
            
            result['privacy_info'] = {
                'has_privacy': True,
                'item_count': len(privacy_items),
                'privacy_types': list(set(item.get('type', 'unknown') for item in privacy_items))
            }
        else:
            processing_log.append("未发现隐私信息")
            result['privacy_info'] = {'has_privacy': False}
    else:
        processing_log.append("隐私脱敏功能已禁用")
        result['privacy_info'] = {'has_privacy': False, 'disabled': True}
    
    # 更新处理后的内容
    result['processed_content'] = content
    processing_log.append("智能内容预处理完成")
    
    return result

def process_user_content(content, content_type='comment', enable_privacy_masking=True):
    """
    统一的用户内容预处理函数
    所有用户生成的内容都应该经过这个函数处理
    
    参数:
    - content: 用户输入的原始内容
    - content_type: 内容类型 ('comment', 'evidence', 'case_description', 'agreement')
    - enable_privacy_masking: 是否启用隐私脱敏
    
    返回:
    {
        'processed_content': str,      # 处理后的内容
        'is_allowed': bool,              # 是否允许发布
        'violation_info': dict,        # 违规信息（如果有）
        'privacy_info': dict,            # 隐私信息处理结果
        'processing_log': list,          # 处理日志
        'user_message': str              # 给用户看的提示信息
    }
    """
    if not content or not content.strip():
        return {
            'processed_content': content,
            'is_allowed': True,
            'violation_info': None,
            'privacy_info': None,
            'processing_log': ['内容为空'],
            'user_message': ''
        }
    
    # 调用智能内容预处理管道
    result = intelligent_content_pipeline(content, enable_privacy_masking)
    
    # 根据内容类型和处理结果生成用户友好的提示信息
    user_message = ''
    
    if not result['is_allowed']:
        violation = result.get('violation_info', {})
        severity = violation.get('severity', 'unknown')
        reason = violation.get('reason', '内容不符合规范')
        
        if severity == 'high':
            user_message = f'内容包含严重违规信息（{reason}），无法发布，请修改后重试'
        elif severity == 'medium':
            user_message = f'内容包含不当信息（{reason}），请修改后重新提交'
        else:
            user_message = f'内容需要调整（{reason}），请检查后再试'
    else:
        # 检查是否有敏感词被替换
        sensitive_info = result.get('sensitive_words_info', {})
        if sensitive_info and sensitive_info.get('has_replacements'):
            replaced_count = sensitive_info.get('replacement_count', 0)
            replaced_words = sensitive_info.get('replaced_words', [])
            
            if replaced_count == 1:
                user_message = f'系统已自动将敏感词替换为****'
            else:
                user_message = f'系统已自动将{replaced_count}个敏感词替换为****'
        
        # 检查是否有隐私信息被处理
        privacy_info = result.get('privacy_info', {})
        if privacy_info and privacy_info.get('has_privacy'):
            item_count = privacy_info.get('item_count', 0)
            privacy_types = privacy_info.get('privacy_types', [])
            
            if content_type == 'comment':
                privacy_msg = f'系统已自动对评论中的 {item_count} 个隐私信息进行脱敏处理'
            elif content_type == 'evidence':
                privacy_msg = f'系统已自动对证据描述中的 {item_count} 个隐私信息进行脱敏处理'
            elif content_type == 'case_description':
                privacy_msg = f'系统已自动对案件描述中的 {item_count} 个隐私信息进行脱敏处理'
            else:
                privacy_msg = f'系统已自动对内容中的 {item_count} 个隐私信息进行脱敏处理'
            
            # 如果同时有敏感词替换和隐私脱敏，合并提示
            if user_message:
                user_message += '，' + privacy_msg
            else:
                user_message = privacy_msg
    
    result['user_message'] = user_message
    return result

def generate_legal_notes(content, case_type):
    # 使用豆包API生成法律注释，返回结构保持一致
    user_prompt = (
        "你是一名法律助理。请基于下面的证据文本，结合案件类型（民事或一般），"
        "给出最相关的中国法律条文引用与简短注释说明。"
        "请仅返回JSON数组，每个元素包含legal_article和note_content两个中文字段。"
        f"\n\n案件类型: {case_type}\n证据内容: {content}"
    )
    messages = [
        {"role": "system", "content": "你是严谨的法律助理，擅长中国法律条文匹配。"},
        {"role": "user", "content": user_prompt}
    ]
    output = doubao_chat(messages)
    if output:
        try:
            parsed = json.loads(output)
            # 期望是list[dict]
            if isinstance(parsed, list):
                normalized = []
                for item in parsed:
                    if isinstance(item, dict):
                        article = item.get('legal_article') or item.get('law') or ''
                        note = item.get('note_content') or item.get('note') or ''
                        if article and note:
                            normalized.append({
                                'legal_article': article,
                                'note_content': note
                            })
                if normalized:
                    return normalized
        except Exception:
            pass
    # 回退：保留原有静态注释
    if case_type == 'civil':
        return [
            {
                'legal_article': '《民法典》第1165条',
                'note_content': '行为人因过错侵害他人民事权益造成损害的，应当承担侵权责任。'
            },
            {
                'legal_article': '《民法典》第1179条',
                'note_content': '侵害他人造成人身损害的，应当赔偿医疗费、护理费、交通费、营养费、住院伙食补助费等为治疗和康复支出的合理费用，以及因误工减少的收入。'
            }
        ]
    return [
        {
            'legal_article': '《民法典》第8条',
            'note_content': '民事主体从事民事活动，不得违反法律，不得违背公序良俗。'
        }
    ]

def check_violent_content(content):
    """增强版网络暴力/不当言论检测。
    - 统一大小写、半角化，移除空白和常见标点后再检测
    - 覆盖更丰富的侮辱词、谐音/缩写（如 sb、shabi、cnm、nmsl 等）
    - 简单但有效的命中策略：只要存在任意词命中即判定为不当
    """
    if not content:
        return False

    def to_halfwidth(s: str) -> str:
        result = []
        for ch in s:
            code = ord(ch)
            if code == 12288:  # 全角空格
                result.append(' ')
            elif 65281 <= code <= 65374:  # 全角字符范围
                result.append(chr(code - 65248))
            else:
                result.append(ch)
        return ''.join(result)

    # 规范化：半角化、lower、去空白和标点
    normalized = to_halfwidth(content).lower()
    normalized = re.sub(r"[\s\W_]+", "", normalized)

    # 更全面的词库（可随数据持续扩充）
    violent_words = [
        # 直接侮辱/诅咒
        '傻逼','煞笔','沙比','猪脑','脑残','神经病','狗东西','畜生','滚蛋','滚开','滚','去死','死吧','cnm','nmsl','你妈','操你','草你','艹你','垃圾','恶心',
        # 缩写/谐音/拼音
        'sb','2b','shabi','shaibi','sha bi','sha b',
        # 变形写法（移除标点后同样可命中）
        'cao ni','cao','gun','ni ma'
    ]

    # 命中检测：在规范化后的字符串中查找
    for word in violent_words:
        w = re.sub(r"[\s\W_]+", "", word)
        if w and w in normalized:
            return True

    return False

def check_violent_content_graded(content):
    """分级网络暴力/不当言论检测。
    策略：
    - 优先使用AI智能审核，回退到传统关键词检测
    - 按severity处理：high/medium -> 屏蔽；low -> 不屏蔽（可用于提示）
    """
    if not content:
        return False
    
    # 首先尝试AI智能审核
    ai_result = ai_content_moderation(content)
    if ai_result and ai_result.get('is_violation'):
        return ai_result.get('severity') in ('high', 'medium')
    
    # AI审核失败时回退到传统关键词检测
    return fallback_content_check(content)

def check_violent_content_high(content):
    if not content:
        return False
    ai_result = ai_content_moderation(content)
    if ai_result and ai_result.get('is_violation'):
        return ai_result.get('severity') == 'high'
    fallback = fallback_content_check(content)
    if fallback and fallback.get('is_violation'):
        return fallback.get('severity') == 'high'
    return False

def replace_sensitive_words(content, replacement='****'):
    """
    敏感词局部替换函数 - 将敏感词替换为指定字符
    返回: {
        'processed_content': str,      # 处理后的内容
        'has_sensitive_words': bool,    # 是否包含敏感词
        'replaced_words': list,         # 被替换的敏感词列表
        'replacement_count': int        # 替换次数
    }
    """
    if not content or not content.strip():
        return {
            'processed_content': content,
            'has_sensitive_words': False,
            'replaced_words': [],
            'replacement_count': 0
        }
    
    original_content = content
    replaced_words = set()
    total_replacements = 0
    
    # 获取所有敏感词（数据库 + 内置词库）
    all_sensitive_words = []
    
    # 从数据库获取敏感词
    try:
        db_words = db.session.query(SensitiveWord).all()
        for word in db_words:
            if word.severity in ('high', 'medium'):  # 只处理中高严重程度的词
                all_sensitive_words.append({
                    'word': word.word,
                    'category': word.category,
                    'severity': word.severity
                })
    except Exception:
        pass
    
    # 添加内置敏感词
    builtin_lexicon = [
        {'word': '傻逼', 'category': 'insult', 'severity': 'high'},
        {'word': '煞笔', 'category': 'insult', 'severity': 'high'},
        {'word': '沙比', 'category': 'insult', 'severity': 'high'},
        {'word': '猪脑', 'category': 'insult', 'severity': 'medium'},
        {'word': '脑残', 'category': 'insult', 'severity': 'medium'},
        {'word': '神经病', 'category': 'insult', 'severity': 'medium'},
        {'word': '垃圾', 'category': 'insult', 'severity': 'medium'},
        {'word': '去死', 'category': 'hate', 'severity': 'high'},
        {'word': '死吧', 'category': 'hate', 'severity': 'high'},
        {'word': '操你', 'category': 'profanity', 'severity': 'high'},
        {'word': '草你', 'category': 'profanity', 'severity': 'high'},
        {'word': '艹你', 'category': 'profanity', 'severity': 'high'},
        {'word': '你妈', 'category': 'profanity', 'severity': 'medium'},
        {'word': 'cnm', 'category': 'profanity', 'severity': 'high'},
        {'word': 'nmsl', 'category': 'hate', 'severity': 'high'},
        {'word': 'sb', 'category': 'insult', 'severity': 'medium'},
        {'word': '2b', 'category': 'insult', 'severity': 'medium'},
        {'word': 'shabi', 'category': 'insult', 'severity': 'high'},
        {'word': 'shaibi', 'category': 'insult', 'severity': 'high'},
        {'word': 'sha bi', 'category': 'insult', 'severity': 'high'},
        {'word': 'sha b', 'category': 'insult', 'severity': 'high'},
        {'word': 'cao ni', 'category': 'profanity', 'severity': 'high'},
        {'word': 'gun', 'category': 'insult', 'severity': 'medium'},
        {'word': 'ni ma', 'category': 'profanity', 'severity': 'medium'},
    ]
    
    for entry in builtin_lexicon:
        all_sensitive_words.append(entry)
    
    # 处理每个敏感词
    processed_content = content
    
    for sensitive_entry in all_sensitive_words:
        sensitive_word = sensitive_entry['word']
        # 使用正则表达式进行替换，支持大小写不敏感和全词匹配
        import re
        # 创建匹配模式，支持变体和空格
        patterns = [
            sensitive_word,  # 原词
            sensitive_word.replace(' ', '\\s*'),  # 支持中间有空格
        ]
        
        for pattern in patterns:
            # 使用正则表达式进行全局替换
            regex_pattern = re.compile(re.escape(pattern), re.IGNORECASE | re.UNICODE)
            matches = regex_pattern.findall(processed_content)
            
            if matches:
                replaced_words.add(sensitive_word)
                total_replacements += len(matches)
                processed_content = regex_pattern.sub(replacement, processed_content)
    
    return {
        'processed_content': processed_content,
        'has_sensitive_words': len(replaced_words) > 0,
        'replaced_words': list(replaced_words),
        'replacement_count': total_replacements
        }

def ai_content_moderation(content):
    """
    使用豆包API进行智能内容审核
    返回: {'is_violation': bool, 'reason': str, 'severity': str}
    """
    if not content or not content.strip():
        return {'is_violation': False, 'reason': '', 'severity': 'none'}
    
    try:
        messages = [
            {"role": "system", "content": """
            你是一个智能内容审核助手，专门识别网络暴力、不当言论、仇恨言论、骚扰信息等。
            请分析以下文本，判断是否存在违规内容。
            
            返回JSON格式：
            {
                "is_violation": boolean,  // 是否违规
                "reason": string,         // 违规原因描述
                "severity": string        // 严重程度: high/medium/low/none
            }
            
            违规类型包括：
            - 人身攻击、侮辱、谩骂
            - 仇恨言论、歧视性语言
            - 骚扰、威胁
            - 色情、低俗内容
            - 虚假信息、谣言
            - 其他违反社区准则的内容
            
            请基于语义理解进行判断，不要仅依赖关键词匹配。
            """},
            {"role": "user", "content": f"请审核以下内容：\n{content}"}
        ]
        
        result = doubao_chat(messages, temperature=0.1)
        if result:
            try:
                parsed = json.loads(result)
                if isinstance(parsed, dict) and 'is_violation' in parsed:
                    return parsed
            except json.JSONDecodeError:
                pass
        
        # 回退到传统关键词检测
        return fallback_content_check(content)
        
    except Exception as e:
        print(f"[AI Content Moderation Error] {e}")
        return fallback_content_check(content)

def fallback_content_check(content):
    """传统内容审核回退方案"""
    normalized = normalize_text(content)
    
    # 基础内置词库（作为后备），按类别与级别
    builtin_lexicon = [
        # insult
        {'word': '傻逼', 'category': 'insult', 'severity': 'high'},
        {'word': '煞笔', 'category': 'insult', 'severity': 'high'},
        {'word': '沙比', 'category': 'insult', 'severity': 'high'},
        {'word': '猪脑', 'category': 'insult', 'severity': 'medium'},
        {'word': '脑残', 'category': 'insult', 'severity': 'medium'},
        {'word': '神经病', 'category': 'insult', 'severity': 'medium'},
        {'word': '垃圾', 'category': 'insult', 'severity': 'medium'},
        {'word': '恶心', 'category': 'insult', 'severity': 'low'},
        # discrimination 示例（可扩展）
        {'word': '低能', 'category': 'discrimination', 'severity': 'medium'},
        # profanity/hate
        {'word': '去死', 'category': 'hate', 'severity': 'high'},
        {'word': '死吧', 'category': 'hate', 'severity': 'high'},
        {'word': '操你', 'category': 'profanity', 'severity': 'high'},
        {'word': '草你', 'category': 'profanity', 'severity': 'high'},
        {'word': '艹你', 'category': 'profanity', 'severity': 'high'},
        {'word': '你妈', 'category': 'profanity', 'severity': 'medium'},
        # abbreviations/pinyin/variants
        {'word': 'cnm', 'category': 'profanity', 'severity': 'high'},
        {'word': 'nmsl', 'category': 'hate', 'severity': 'high'},
        {'word': 'sb', 'category': 'insult', 'severity': 'medium'},
        {'word': '2b', 'category': 'insult', 'severity': 'medium'},
        {'word': 'shabi', 'category': 'insult', 'severity': 'high'},
        {'word': 'shaibi', 'category': 'insult', 'severity': 'high'},
        {'word': 'sha bi', 'category': 'insult', 'severity': 'high'},
        {'word': 'sha b', 'category': 'insult', 'severity': 'high'},
        {'word': 'cao ni', 'category': 'profanity', 'severity': 'high'},
        {'word': 'gun', 'category': 'insult', 'severity': 'medium'},
        {'word': 'ni ma', 'category': 'profanity', 'severity': 'medium'},
    ]

    # 组合数据库词库
    try:
        db_words = db.session.query(SensitiveWord).all()
    except Exception:
        db_words = []

    # 统一规范化对比
    def matches(entry_word: str) -> bool:
        w = normalize_text(entry_word)
        return bool(w) and (w in normalized)

    # 先检查数据库词库
    for sw in db_words:
        if matches(sw.word):
            if sw.severity in ('high', 'medium'):
                return {'is_violation': True, 'reason': f'包含敏感词: {sw.word}', 'severity': sw.severity}
            # low级别不屏蔽

    # 再检查内置词库
    for entry in builtin_lexicon:
        if matches(entry['word']):
            if entry['severity'] in ('high', 'medium'):
                return {'is_violation': True, 'reason': f'包含不当内容: {entry["word"]}', 'severity': entry['severity']}
            # low级别不屏蔽

    return {'is_violation': False, 'reason': '', 'severity': 'none'}

def generate_timeline_events(evidences):
    # 保留原逻辑（本函数暂不接入AI）
    events = []
    for evidence in sorted(evidences, key=lambda e: e.created_at):
        events.append({
            'description': f'{evidence.submitter.username}提交了{"关键" if evidence.is_key else ""}证据',
            'created_at': evidence.created_at
        })
    return events

def generate_mediation_agreement(case, initiator, opponent):
    # 使用豆包API生成调解协议书，保持返回字符串格式
    # 汇总证据信息（简要）
    all_evidences = db.session.query(Evidence).filter_by(case_id=case.id).order_by(Evidence.created_at.asc()).all()
    def fmt_ev(e):
        base = (e.content[:100] + '...') if e.content else f"[{e.evidence_type}文件]"
        if e.is_key:
            base += "（关键证据）"
        if e.is_proxy:
            base += "（代对峙方举证）"
        return base
    initiator_evidences = [fmt_ev(e) for e in all_evidences if e.submitter_id == case.initiator_id and not e.is_proxy][:5]
    opponent_evidences = [fmt_ev(e) for e in all_evidences if e.submitter_id != case.initiator_id or e.is_proxy][:5]

    user_prompt = (
        "你是一名法律调解助理。请根据案件描述与双方代表性证据，"
        "用中文输出一份结构化的调解协议书（Markdown），包含：基本信息、案件事实确认、相关法律依据、调解条款、签署确认。"
        "语气中立、措辞严谨。"
        f"\n\n案件标题: {case.title}\n案件类型: {case.case_type}\n案件编号: {case.id}\n发起方: {initiator.username}\n对峙方: {opponent.username if opponent else '[待定]'}\n"
        f"案件描述: {case.description}\n"
        f"发起方证据示例: {json.dumps(initiator_evidences, ensure_ascii=False)}\n"
        f"对峙方证据示例: {json.dumps(opponent_evidences, ensure_ascii=False)}\n"
        "请直接输出Markdown文本，不要包含额外解释。"
    )
    messages = [
        {"role": "system", "content": "你是法律调解助理，负责生成规范的中文调解协议书。"},
        {"role": "user", "content": user_prompt}
    ]
    output = doubao_chat(messages)
    if output and isinstance(output, str) and len(output.strip()) > 0:
        return output
    # 回退到原始模板（保证功能可用）
    facts_summary = f"""# AI智能总结案件事实\n\n{case.description}\n\n## 证据分析\n- 发起方：{'; '.join(initiator_evidences)}\n- 对峙方：{'; '.join(opponent_evidences)}\n"""
    agreement = f"""# 调解协议书\n\n## 基本信息\n甲方（发起方）：{initiator.username}\n乙方（对峙方）：{opponent.username if opponent else '[待定]'}\n\n案件名称：{case.title}\n案件类型：{'民事案件' if case.case_type == 'civil' else '泛式讨论'}\n案件编号：{case.id}\n\n## 案件事实确认\n{facts_summary}\n\n## 调解协议内容\n经双方当事人自愿协商一致，达成如下调解协议：\n\n1. 双方一致同意通过友好协商方式解决本纠纷\n2. 双方确认上述案件事实无误\n3. 本协议自双方签字之日起生效\n4. 本协议一式两份，双方各执一份，具有同等法律效力\n\n## 签署确认\n\n甲方（签名）：_________________       日期：_________________\n\n乙方（签名）：_________________       日期：_________________\n"""
    return agreement

# 证据类型智能分类（可选：当evidence_type为auto时启用）
def classify_evidence_type(text):
    prompt = (
        "根据给定文本内容判断证据类型，候选：text、image、audio、video、file。"
        "如果是聊天记录、合同等纯文本，请返回text。仅返回一个候选字符串。\n\n"
        f"文本：{text}"
    )
    messages = [
        {"role": "system", "content": "你是证据分类器，只返回类别关键词。"},
        {"role": "user", "content": prompt}
    ]
    output = doubao_chat(messages)
    if output:
        label = output.strip().lower()
        if label in {"text", "image", "audio", "video", "file"}:
            return label
    return "text"

# 路由函数
@app.route('/')
def index():
    # 获取分类参数
    category = request.args.get('category', 'all')
    
    # 根据分类筛选案件
    if category == 'civil':
        cases = db.session.query(Case).filter_by(case_type='civil').order_by(Case.created_at.desc()).all()
    elif category == 'general':
        cases = db.session.query(Case).filter_by(case_type='general').order_by(Case.created_at.desc()).all()
    else:
        cases = db.session.query(Case).order_by(Case.created_at.desc()).all()
    
    # 计算每个案件的支持数
    case_support_counts = {}
    for case in cases:
        initiator_supports = db.session.query(Support).filter_by(case_id=case.id, side='initiator').count()
        opponent_supports = db.session.query(Support).filter_by(case_id=case.id, side='opponent').count()
        case_support_counts[case.id] = {
            'initiator': initiator_supports,
            'opponent': opponent_supports
        }
    
    return render_template('index.html', 
                           cases=cases, 
                           category=category,
                           case_support_counts=case_support_counts,
                           current_user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        try:
            print('[REGISTER] received', {'username': username, 'email': email, 'len_password': len(password)})
        except Exception:
            pass
        
        # 检查用户是否已存在
        try:
            existing_u = db.session.query(User).filter_by(username=username).first()
            print('[REGISTER] query username exists:', bool(existing_u))
        except Exception as e:
            print('[REGISTER] error checking username:', repr(e))
            traceback.print_exc()
            flash('数据库错误：无法检查用户名是否存在', 'error')
            return redirect(url_for('register'))
        if existing_u:
            flash('用户名已存在', 'error')
            return redirect(url_for('register'))
        try:
            existing_e = db.session.query(User).filter_by(email=email).first()
            print('[REGISTER] query email exists:', bool(existing_e))
        except Exception as e:
            print('[REGISTER] error checking email:', repr(e))
            traceback.print_exc()
            flash('数据库错误：无法检查邮箱是否存在', 'error')
            return redirect(url_for('register'))
        if existing_e:
            flash('邮箱已被注册', 'error')
            return redirect(url_for('register'))
        
        # 创建新用户
        user = User(username=username, email=email)
        user.set_password(password)
        try:
            db.session.add(user)
            db.session.commit()
            print('[REGISTER] commit ok for user_id:', user.id)
        except Exception as e:
            db.session.rollback()
            print('[REGISTER] commit failed:', repr(e))
            traceback.print_exc()
            flash('数据库错误：注册失败，请稍后再试', 'error')
            return redirect(url_for('register'))
        
        flash('注册成功，请登录', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# 诊断：注册流程调试端点
@app.route('/api/test/register_debug', methods=['POST'])
def api_test_register_debug():
    try:
        payload = request.get_json(silent=True) or {}
        username = payload.get('username') or f'debug_{uuid.uuid4().hex[:8]}'
        email = payload.get('email') or f'{uuid.uuid4().hex[:8]}@example.com'
        password = payload.get('password') or 'Pass1234!'
        print('[REGISTER_DEBUG] payload:', {'username': username, 'email': email})
        # 重用与注册相同逻辑但返回 JSON
        exists_u = db.session.query(User).filter_by(username=username).first()
        exists_e = db.session.query(User).filter_by(email=email).first()
        if exists_u or exists_e:
            return jsonify({'ok': False, 'msg': 'exists', 'username_exists': bool(exists_u), 'email_exists': bool(exists_e)}), 200
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return jsonify({'ok': True, 'user_id': user.id}), 200
    except Exception as e:
        db.session.rollback()
        traceback.print_exc()
        return jsonify({'ok': False, 'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = db.session.query(User).filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        
        flash('用户名或密码错误', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/create_case', methods=['GET', 'POST'])
@login_required
def create_case():
    if request.method == 'POST':
        title = request.form['title']
        case_type = request.form['case_type']
        description = request.form['description']
        
        # 对案件描述进行AI智能处理
        description_result = process_user_content(description, content_type='case_description', enable_privacy_masking=True)
        if not description_result['is_allowed']:
            violation_info = description_result.get('violation_info', {})
            severity = violation_info.get('severity', 'unknown')
            reason = violation_info.get('reason', '内容不符合规范')
            flash(f'案件描述包含违规内容（{severity}）: {reason}，请修改后重试', 'error')
            return redirect(url_for('create_case'))
        
        # 使用处理后的案件描述
        processed_description = description_result['processed_content']
        
        # 检查是否提交了证据
        evidence_content = request.form.get('evidence_content', '').strip()
        evidence_type = request.form.get('evidence_type', 'text')
        is_key = 'is_key' in request.form
        has_file = 'evidence_file' in request.files and request.files['evidence_file'].filename != ''
        
        # 验证：必须提交至少一个证据
        if not evidence_content and not has_file:
            flash('发起案件时必须提交至少一个证据', 'error')
            return redirect(url_for('create_case'))
        
        # 对证据内容进行AI智能处理（如果有文本内容）
        processed_evidence_content = evidence_content
        if evidence_content:
            evidence_result = process_user_content(evidence_content, content_type='evidence', enable_privacy_masking=True)
            if not evidence_result['is_allowed']:
                violation_info = evidence_result.get('violation_info', {})
                severity = violation_info.get('severity', 'unknown')
                reason = violation_info.get('reason', '内容不符合规范')
                flash(f'证据内容包含违规信息（{severity}）: {reason}，请修改后重试', 'error')
                return redirect(url_for('create_case'))
            
            processed_evidence_content = evidence_result['processed_content']
            
            # 如果有用户提示信息，显示给用户
            if evidence_result.get('user_message'):
                flash(evidence_result['user_message'], 'info')
        
        # 创建案件
        case = Case(
            title=title,
            case_type=case_type,
            description=processed_description,  # 使用AI处理后的描述
            initiator_id=current_user.id,
            status='ongoing'  # 直接设为进行中，因为已有证据
        )
        db.session.add(case)
        db.session.flush()  # 获取case.id但不提交事务
        
        # 处理证据提交
        file_path = None
        file_type = None
        
        # 智能分类（当选择auto时，根据内容/文件自动判定类型）
        if evidence_type == 'auto':
            if has_file:
                # 根据文件扩展名推断类型
                filename_for_type = request.files['evidence_file'].filename
                evidence_type = get_file_type(filename_for_type)
            elif evidence_content:
                evidence_type = classify_evidence_type(evidence_content)
            else:
                evidence_type = 'text'

        # 处理文件上传
        if has_file:
            file = request.files['evidence_file']
            if allowed_file(file.filename, evidence_type):
                filename = generate_unique_filename(file.filename)
                # 为每个案件创建单独的文件夹
                case_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(case.id))
                if not os.path.exists(case_folder):
                    os.makedirs(case_folder)
                
                file_path = os.path.join(case_folder, filename)
                file.save(file_path)
                # 存储相对路径
                file_path = os.path.join(str(case.id), filename)
                file_type = file.filename.rsplit('.', 1)[1].lower()
            else:
                db.session.rollback()
                flash('不支持的文件类型', 'error')
                return redirect(url_for('create_case'))
        
        # 创建证据
        evidence = Evidence(
            case_id=case.id,
            submitter_id=current_user.id,
            content=processed_evidence_content,  # 使用AI处理后的证据内容
            file_path=file_path,
            evidence_type=evidence_type,
            file_type=file_type,
            is_key=is_key,
            status='complete'
        )
        db.session.add(evidence)
        
        # 添加时间线事件
        timeline_description = f'{current_user.username}发起了案件并提交了'
        if is_key:
            timeline_description += '关键'
        timeline_description += '证据'
        timeline_event = TimelineEvent(
            case_id=case.id,
            description=timeline_description
        )
        db.session.add(timeline_event)
        
        # 提交所有更改
        db.session.commit()
        
        flash('案件创建成功', 'success')
        return redirect(url_for('case_detail', case_id=case.id))
    
    return render_template('create_case.html')

@app.route('/case/<int:case_id>')
def case_detail(case_id):
    case = Case.query.get_or_404(case_id)
    
    # 获取双方证据
    initiator_evidences = []
    opponent_evidences = []
    
    # 使用兼容的查询方式，按创建时间倒序排列
    evidences = db.session.query(Evidence).filter_by(case_id=case_id).order_by(Evidence.created_at.asc()).all()
    for evidence in evidences:
        # 处理隐私信息（仅文本内容）
        if evidence.content:
            evidence.content = process_privacy_removal(evidence.content)
        
        # 生成法律注释（模拟）- 仅对有文本内容的证据
        if evidence.content and not evidence.legal_notes:
            legal_notes = generate_legal_notes(evidence.content, case.case_type)
            for note in legal_notes:
                legal_note = EvidenceLegalNote(
                    evidence_id=evidence.id,
                    legal_article=note['legal_article'],
                    note_content=note['note_content']
                )
                db.session.add(legal_note)
            db.session.commit()
        
        # 优化要求3：证据分组
        # civil：维持原逻辑（发起方且非代举证 -> 发起方，否则 -> 对峙方）
        # general：依据is_proxy代表提交到对峙方(True)或发起方(False)
        if case.case_type == 'civil':
            if evidence.submitter_id == case.initiator_id and not evidence.is_proxy:
                initiator_evidences.append(evidence)
            else:
                opponent_evidences.append(evidence)
        else:
            if evidence.is_proxy:
                opponent_evidences.append(evidence)
            else:
                initiator_evidences.append(evidence)
    
    # 证据排序：关键证据置顶，点赞多优先，其次按创建时间
    initiator_evidences.sort(key=lambda e: (0 if getattr(e, 'is_key', False) else 1, -getattr(e, 'likes', 0), getattr(e, 'created_at', None)))
    opponent_evidences.sort(key=lambda e: (0 if getattr(e, 'is_key', False) else 1, -getattr(e, 'likes', 0), getattr(e, 'created_at', None)))

    # 按证据类型分组
    initiator_evidence_groups = {}
    for evidence in initiator_evidences:
        if evidence.evidence_type not in initiator_evidence_groups:
            initiator_evidence_groups[evidence.evidence_type] = []
        initiator_evidence_groups[evidence.evidence_type].append(evidence)
    
    opponent_evidence_groups = {}
    for evidence in opponent_evidences:
        if evidence.evidence_type not in opponent_evidence_groups:
            opponent_evidence_groups[evidence.evidence_type] = []
        opponent_evidence_groups[evidence.evidence_type].append(evidence)
    
    # 获取评论（点赞排序）
    comments = db.session.query(Comment).filter_by(case_id=case_id).order_by(Comment.likes.desc()).all()
    # 复检历史评论并自动屏蔽命中不当言论
    changed = False
    for c in comments:
        try:
            if not c.is_blocked and check_violent_content_high(c.content):
                c.is_blocked = True
                changed = True
        except Exception:
            pass
    if changed:
        db.session.commit()
    
    # 检查是否可以评论
    can_comment = True
    if case.case_type == 'civil':
        can_comment = len(initiator_evidences) > 0 and len(opponent_evidences) > 0
    
    # 获取支持数统计
    initiator_supports = db.session.query(Support).filter_by(case_id=case_id, side='initiator').count()
    opponent_supports = db.session.query(Support).filter_by(case_id=case_id, side='opponent').count()
    total_supports = initiator_supports + opponent_supports
    
    support_percentages = {
        'initiator': (initiator_supports / total_supports * 100) if total_supports > 0 else 0,
        'opponent': (opponent_supports / total_supports * 100) if total_supports > 0 else 0
    }
    
    # 获取用户支持情况
    user_support = None
    if current_user.is_authenticated:
        support = db.session.query(Support).filter_by(user_id=current_user.id, case_id=case_id).first()
        if support:
            user_support = support.side

    # 构建评论作者支持映射，用于模板显示“支持方”
    comment_support_map = {}
    unique_author_ids = {c.author_id for c in comments}
    if unique_author_ids:
        supports = db.session.query(Support).filter(Support.case_id == case_id, Support.user_id.in_(list(unique_author_ids))).all()
        comment_support_map = {s.user_id: s.side for s in supports}
    
    # 获取调解协议
    mediation_agreement = db.session.query(MediationAgreement).filter_by(case_id=case_id).first()
    
    # 获取现有的时间线事件
    timeline_events = db.session.query(TimelineEvent).filter_by(case_id=case_id).order_by(TimelineEvent.created_at.desc()).all()
    
    return render_template('case_detail.html',
                          case=case,
                          initiator_evidences=initiator_evidences,
                          opponent_evidences=opponent_evidences,
                          initiator_evidence_groups=initiator_evidence_groups,
                          opponent_evidence_groups=opponent_evidence_groups,
                          comments=comments,
                          can_comment=can_comment,
                          user_support=user_support,
                          comment_support_map=comment_support_map,
                          mediation_agreement=mediation_agreement,
                          timeline_events=timeline_events,
                          support_counts={'initiator': initiator_supports, 'opponent': opponent_supports},
                          support_percentages=support_percentages,
                          current_user=current_user)

@app.route('/submit_evidence/<int:case_id>', methods=['POST'])
@login_required
def submit_evidence(case_id):
    case = db.session.query(Case).get_or_404(case_id)
    content = request.form.get('content', '')
    evidence_type = request.form.get('evidence_type', 'text')
    is_key = 'is_key' in request.form
    is_proxy = 'is_proxy' in request.form
    # 泛式讨论允许用户自主选择提交方（发起方/对峙方）
    submit_side = request.form.get('submit_to')
    file_path = None
    file_type = None
    
    # civil：维持代举证权限仅限发起方；general：根据submit_to决定is_proxy
    if case.case_type == 'civil':
        if is_proxy and not (current_user.id == case.initiator_id):
            flash('无权代举证', 'error')
            return redirect(url_for('case_detail', case_id=case_id))
    else:
        if submit_side in ['initiator', 'opponent']:
            # general中用is_proxy来表示提交到对峙方(True)或发起方(False)
            is_proxy = (submit_side == 'opponent')
    
    # 智能分类（当选择auto时，根据内容/文件自动判定类型）
    if evidence_type == 'auto':
        has_file = ('evidence_file' in request.files and request.files['evidence_file'].filename != '')
        if has_file:
            filename_for_type = request.files['evidence_file'].filename
            evidence_type = get_file_type(filename_for_type)
        elif content:
            evidence_type = classify_evidence_type(content)
        else:
            evidence_type = 'text'

    # 处理文件上传（优先Supabase存储，回退本地）
    if evidence_type != 'text' and 'evidence_file' in request.files:
        file = request.files['evidence_file']
        if file.filename != '':
            if allowed_file(file.filename, evidence_type):
                filename = generate_unique_filename(file.filename)
                file_type = file.filename.rsplit('.', 1)[1].lower()
                # 如果配置了 Supabase，则惰性获取客户端并上传到存储桶
                client = get_supabase_client()
                if client:
                    try:
                        # 确保存储桶存在
                        ensure_supabase_bucket(client, SUPABASE_BUCKET)
                        # 构造云端路径：<case_id>/<filename>
                        cloud_path = f"{case_id}/{filename}"
                        # 读取文件字节并上传
                        file_bytes = file.read()
                        client.storage.from_(SUPABASE_BUCKET).upload(cloud_path, file_bytes, file_options={"contentType": file.mimetype})
                        # 生成公开访问URL
                        public_url = client.storage.from_(SUPABASE_BUCKET).get_public_url(cloud_path)
                        file_path = public_url
                    except Exception as e:
                        print('Supabase upload failed, fallback to local:', e)
                
                # 如果没有Supabase或上传失败，则回退到本地
                if not file_path:
                    case_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(case_id))
                    if not os.path.exists(case_folder):
                        os.makedirs(case_folder)
                    local_path = os.path.join(case_folder, filename)
                    # 注意：如果此前读取过file.read()，需要seek(0)再保存
                    try:
                        file.stream.seek(0)
                    except Exception:
                        pass
                    file.save(local_path)
                    file_path = os.path.join(str(case_id), filename)
            else:
                flash('不支持的文件类型', 'error')
                return redirect(url_for('case_detail', case_id=case_id))
    
    # 验证：不能只提交文本作为证据
    if evidence_type == 'text' and not content:
        flash('请输入证据描述', 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    
    # 智能内容预处理（仅对文本内容进行审核和脱敏）
    processed_content = content
    if content and evidence_type == 'text':
        # 使用统一的内容预处理函数
        processing_result = process_user_content(content, content_type='evidence', enable_privacy_masking=True)
        
        if not processing_result['is_allowed']:
            violation_info = processing_result.get('violation_info', {})
            severity = violation_info.get('severity', 'unknown')
            reason = violation_info.get('reason', '内容不符合规范')
            
            flash(f'内容审核未通过（{severity}）: {reason}', 'error')
            return redirect(url_for('case_detail', case_id=case_id))
        
        # 使用处理后的内容
        processed_content = processing_result['processed_content']
        
        # 如果有用户提示信息，显示给用户
        if processing_result.get('user_message'):
            flash(processing_result['user_message'], 'info')
    
    # 创建证据
    evidence = Evidence(
        case_id=case_id,
        submitter_id=current_user.id,
        content=processed_content,
        file_path=file_path,
        evidence_type=evidence_type,
        file_type=file_type,
        is_key=is_key,
        is_proxy=is_proxy,
        status='complete'  # 模拟AI判断
    )
    db.session.add(evidence)
    
    # 更新案件状态
    if case.status == 'pending':
        case.status = 'ongoing'
    
    # 更新对峙方信息
    if not case.opponent_id and case.case_type == 'civil' and not is_proxy and current_user.id != case.initiator_id:
        case.opponent_id = current_user.id
    
    # 添加时间线事件
    timeline_event = TimelineEvent(
        case_id=case_id,
        description=f'{current_user.username}提交了{"关键" if is_key else ""}{"代对峙方" if is_proxy else ""}{evidence_type}证据{"（开庭时提交）" if case.status == "ongoing" else ""}'
    )
    db.session.add(timeline_event)
    
    db.session.commit()
    
    flash('证据提交成功', 'success')
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/mark_key_evidence/<int:evidence_id>', methods=['POST'])
@login_required
def mark_key_evidence(evidence_id):
    evidence = db.session.query(Evidence).get_or_404(evidence_id)
    case = evidence.case
    
    # 检查权限
    if current_user.id != evidence.submitter_id and current_user.id != case.initiator_id:
        flash('无权标记此证据', 'error')
        return redirect(url_for('case_detail', case_id=case.id))
    
    # 切换关键标记
    evidence.is_key = not evidence.is_key
    db.session.commit()
    
    flash(f'证据已{"标记为" if evidence.is_key else "取消标记"}关键证据', 'success')
    return redirect(url_for('case_detail', case_id=case.id))

# 获取证据详情API
@app.route('/api/evidence/<int:evidence_id>')
def get_evidence_details(evidence_id):
    evidence = Evidence.query.get(evidence_id)
    if not evidence:
        return jsonify({'error': '证据不存在'}), 404
    
    # 获取提交者信息
    submitter = User.query.get(evidence.submitter_id)
    
    # 构建返回数据
    evidence_data = {
        'id': evidence.id,
        'case_id': evidence.case_id,
        'submitter_name': submitter.username if submitter else '未知用户',
        'submitter_id': evidence.submitter_id,
        'content': evidence.content,
        'file_path': evidence.file_path,
        'file_type': evidence.file_type,
        'evidence_type': evidence.evidence_type,
        'created_at': evidence.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'is_key': evidence.is_key,
        'is_proxy': evidence.is_proxy,
        'likes': evidence.likes,
        'status': evidence.status
    }
    
    return jsonify(evidence_data)

@app.route('/like_evidence/<int:evidence_id>', methods=['POST'])
@login_required
def like_evidence(evidence_id):
    evidence = db.session.query(Evidence).get_or_404(evidence_id)
    
    # 检查是否已经点赞
    existing_like = db.session.query(EvidenceLike).filter_by(user_id=current_user.id, evidence_id=evidence_id).first()
    if existing_like:
        flash('您已点赞此证据', 'error')
        return redirect(url_for('case_detail', case_id=evidence.case_id))
    
    # 添加点赞记录
    like = EvidenceLike(user_id=current_user.id, evidence_id=evidence_id)
    db.session.add(like)
    evidence.likes += 1
    db.session.commit()
    
    return redirect(url_for('case_detail', case_id=evidence.case_id))

@app.route('/add_comment/<int:case_id>', methods=['POST'])
@login_required
def add_comment(case_id):
    case = db.session.query(Case).get_or_404(case_id)
    content = request.form['content']
    
    # 检查是否可以评论
    if case.case_type == 'civil':
        initiator_evidences = db.session.query(Evidence).filter_by(case_id=case_id, submitter_id=case.initiator_id).count()
        opponent_evidences = db.session.query(Evidence).filter(
            (Evidence.case_id == case_id) & ((Evidence.submitter_id != case.initiator_id) | (Evidence.is_proxy == True))
        ).count()
        if initiator_evidences == 0 or opponent_evidences == 0:
            flash('民事案件需要双方都提交证据后才能评论', 'error')
            return redirect(url_for('case_detail', case_id=case_id))

    # 需先选择支持方才能评论
    support = db.session.query(Support).filter_by(user_id=current_user.id, case_id=case_id).first()
    if not support:
        flash('请先在PK条选择支持某一方后再发表评论', 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    
    # 使用AI智能内容预处理
    processing_result = process_user_content(content, content_type='comment', enable_privacy_masking=True)
    
    # 检查是否允许发布
    if not processing_result['is_allowed']:
        violation_info = processing_result.get('violation_info', {})
        severity = violation_info.get('severity', 'unknown')
        reason = violation_info.get('reason', '内容不符合规范')
        
        # 严重违规直接拒绝
        if severity == 'high':
            flash(f'评论包含严重违规内容（{reason}），无法发布，请修改后重试', 'error')
            return redirect(url_for('case_detail', case_id=case_id))
        else:
            flash(f'评论包含不当内容（{reason}），请修改后重新提交', 'error')
            return redirect(url_for('case_detail', case_id=case_id))
    
    # 创建评论：保存原始与处理后的内容，默认允许发布（仅严重违规整体拒绝）
    processed_content = processing_result['processed_content']
    is_blocked = not processing_result['is_allowed']  # 严重违规（high）才不允许发布

    comment = Comment(
        case_id=case_id,
        author_id=current_user.id,
        content=content,  # 保存原始内容
        processed_content=processed_content,  # 保存处理后的内容（敏感词已替换）
        is_blocked=is_blocked,
        violation_reason=(
            processing_result.get('violation_info', {})
            .get('reason') if is_blocked else None
        )
    )
    db.session.add(comment)
    db.session.commit()
    
    # 如果有用户提示信息，显示给用户
    if processing_result.get('user_message'):
        flash(processing_result['user_message'], 'info')
    elif is_blocked:
        flash('您的评论包含不当内容，已被系统处理', 'error')
    else:
        flash('评论发表成功', 'success')
    
    return redirect(url_for('case_detail', case_id=case_id))

@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@login_required
def like_comment(comment_id):
    comment = db.session.query(Comment).get_or_404(comment_id)
    
    # 检查是否已经点赞
    existing_like = db.session.query(CommentLike).filter_by(user_id=current_user.id, comment_id=comment_id).first()
    if existing_like:
        flash('您已点赞此评论', 'error')
        return redirect(url_for('case_detail', case_id=comment.case_id))
    
    # 添加点赞记录
    like = CommentLike(user_id=current_user.id, comment_id=comment_id)
    db.session.add(like)
    comment.likes += 1
    db.session.commit()
    
    return redirect(url_for('case_detail', case_id=comment.case_id))

# ---------------- 管理员：敏感词管理与批量复检 ----------------
@app.route('/admin/sensitive_words', methods=['GET', 'POST'])
@admin_required
def admin_sensitive_words():
    if request.method == 'POST':
        word = request.form.get('word', '').strip()
        category = request.form.get('category', '').strip() or 'insult'
        severity = request.form.get('severity', '').strip() or 'medium'
        if not word:
            flash('词条不能为空', 'error')
            return redirect(url_for('admin_sensitive_words'))
        # 防重复：按原始词唯一
        exists = db.session.query(SensitiveWord).filter_by(word=word).first()
        if exists:
            flash('该词已存在', 'error')
            return redirect(url_for('admin_sensitive_words'))
        sw = SensitiveWord(word=word, category=category, severity=severity)
        db.session.add(sw)
        db.session.commit()
        flash('已添加敏感词', 'success')
        return redirect(url_for('admin_sensitive_words'))
    # GET 显示列表
    words = db.session.query(SensitiveWord).order_by(SensitiveWord.updated_at.desc()).all()
    return render_template('admin_sensitive_words.html', words=words)

@app.route('/admin/sensitive_words/<int:word_id>/delete', methods=['POST'])
@admin_required
def admin_delete_sensitive_word(word_id):
    sw = db.session.query(SensitiveWord).get_or_404(word_id)
    db.session.delete(sw)
    db.session.commit()
    flash('已删除敏感词', 'success')
    return redirect(url_for('admin_sensitive_words'))

@app.route('/admin/recheck', methods=['GET', 'POST'])
@admin_required
def admin_recheck():
    stats = {
        'total_comments': db.session.query(Comment).count(),
        'blocked_comments': db.session.query(Comment).filter_by(is_blocked=True).count(),
        'total_evidences': db.session.query(Evidence).count(),
        'blocked_evidences': db.session.query(Evidence).filter_by(is_blocked=True).count(),
    }
    result = None
    if request.method == 'POST':
        case_id_str = request.form.get('case_id', '').strip()
        query = db.session.query(Comment)
        if case_id_str:
            try:
                cid = int(case_id_str)
                query = query.filter_by(case_id=cid)
            except Exception:
                flash('案件ID无效', 'error')
                return redirect(url_for('admin_recheck'))
        comments = query.order_by(Comment.created_at.asc()).all()
        scanned = len(comments)
        newly_blocked = 0
        for c in comments:
            try:
                if not c.is_blocked and check_violent_content_high(c.content):
                    c.is_blocked = True
                    newly_blocked += 1
            except Exception:
                pass
        if newly_blocked > 0:
            db.session.commit()
        result = {
            'scanned': scanned,
            'newly_blocked': newly_blocked,
        }
        flash(f"复检完成：扫描{scanned}条，新增屏蔽{newly_blocked}条", 'success')
    return render_template('admin_recheck.html', stats=stats, result=result)

@app.route('/admin/processed_content')
@admin_required
def admin_processed_content():
    """管理员查看被处理内容和原因"""
    # 获取所有被屏蔽的评论
    blocked_comments = db.session.query(Comment).filter_by(is_blocked=True).order_by(Comment.created_at.desc()).all()
    
    # 获取所有被屏蔽的证据
    blocked_evidences = db.session.query(Evidence).filter_by(is_blocked=True).order_by(Evidence.created_at.desc()).all()
    
    # 获取所有包含违规信息的调解协议
    blocked_agreements = db.session.query(MediationAgreement).filter(
        MediationAgreement.violation_reason.isnot(None)
    ).order_by(MediationAgreement.created_at.desc()).all()
    
    # 获取处理统计信息
    stats = {
        'total_blocked_comments': len(blocked_comments),
        'total_blocked_evidences': len(blocked_evidences),
        'total_blocked_agreements': len(blocked_agreements),
        'recent_blocks': db.session.query(Comment).filter_by(is_blocked=True).filter(
            Comment.created_at >= datetime.utcnow() - timedelta(days=7)
        ).count() + db.session.query(Evidence).filter_by(is_blocked=True).filter(
            Evidence.created_at >= datetime.utcnow() - timedelta(days=7)
        ).count()
    }
    
    return render_template('admin_processed_content.html', 
                         blocked_comments=blocked_comments,
                         blocked_evidences=blocked_evidences,
                         blocked_agreements=blocked_agreements,
                         stats=stats)

# 实时敏感词检测API
@app.route('/api/detect-sensitive-words', methods=['POST'])
def detect_sensitive_words_api():
    """实时检测敏感词API，用于用户输入时的预警"""
    try:
        data = request.get_json()
        # 兼容不同前端参数名：content 或 text
        content = (data.get('content') or data.get('text') or '').strip()
        
        if not content:
            return jsonify({
                'has_sensitive': False,
                'sensitive_words': [],
                'message': ''
            })
        
        # 获取敏感词列表
        all_sensitive_words = []
        
        # 从数据库获取敏感词
        try:
            db_words = db.session.query(SensitiveWord).all()
            for word in db_words:
                if word.severity in ('high', 'medium'):  # 只处理中高严重程度的词
                    all_sensitive_words.append(word.word)
        except Exception:
            pass
        
        # 添加内置敏感词
        builtin_lexicon = [
            '傻逼', '煞笔', '沙比', '猪脑', '脑残', '神经病', '垃圾',
            '去死', '死吧', '操你', '草你', '艹你', '你妈', 'cnm', 'nmsl',
            'sb', '2b', 'shabi', 'shaibi', 'sha bi', 'sha b', 'cao ni',
            'gun', 'ni ma'
        ]
        
        for word in builtin_lexicon:
            if word not in all_sensitive_words:
                all_sensitive_words.append(word)
        
        sensitive_words = all_sensitive_words
        
        # 检测敏感词
        found_words = []
        content_lower = content.lower()
        
        for word in sensitive_words:
            word_lower = word.lower()
            if word_lower in content_lower:
                found_words.append(word)
        
        # 返回检测结果
        if found_words:
            return jsonify({
                'has_sensitive': True,
                'sensitive_words': found_words,
                'message': f'检测到敏感词：{", ".join(found_words)}，发布时将被替换为****'
            })
        else:
            return jsonify({
                'has_sensitive': False,
                'sensitive_words': [],
                'message': ''
            })
    
    except Exception as e:
        return jsonify({
            'has_sensitive': False,
            'sensitive_words': [],
            'message': f'检测失败：{str(e)}'
        }), 500

@app.route('/support_side/<int:case_id>/<side>', methods=['POST'])
@login_required
def support_side(case_id, side):
    case = db.session.query(Case).get_or_404(case_id)
    
    # 检查支持方是否有效
    if side not in ['initiator', 'opponent']:
        flash('无效的支持操作', 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    
    # 检查是否已经支持过
    existing_support = db.session.query(Support).filter_by(user_id=current_user.id, case_id=case_id).first()
    if existing_support:
        flash('您已选择支持方，无法更改', 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    else:
        # 创建新的支持记录
        support = Support(user_id=current_user.id, case_id=case_id, side=side)
        db.session.add(support)
    
    db.session.commit()
    flash(f'成功支持{"发起方" if side == "initiator" else "对峙方"}', 'success')
    return redirect(url_for('case_detail', case_id=case_id))

# 支持数API（用于AJAX动态更新PK条）
@app.route('/api/support_counts/<int:case_id>')
@login_required
def api_support_counts(case_id):
    case = db.session.query(Case).get_or_404(case_id)
    initiator_supports = db.session.query(Support).filter_by(case_id=case_id, side='initiator').count()
    opponent_supports = db.session.query(Support).filter_by(case_id=case_id, side='opponent').count()
    total_supports = initiator_supports + opponent_supports
    initiator_percent = (initiator_supports / total_supports * 100) if total_supports > 0 else 50
    opponent_percent = (opponent_supports / total_supports * 100) if total_supports > 0 else 50
    return jsonify({
        'initiator_supports': initiator_supports,
        'opponent_supports': opponent_supports,
        'total_supports': total_supports,
        'initiator_percent': round(initiator_percent, 1),
        'opponent_percent': round(opponent_percent, 1)
    })

@app.route('/api/support/<int:case_id>/<side>', methods=['POST'])
@login_required
def api_support(case_id, side):
    # 复用支持逻辑，但返回JSON
    case = db.session.query(Case).get_or_404(case_id)
    if side not in ['initiator', 'opponent']:
        return jsonify({'error': 'invalid_side'}), 400
    existing_support = db.session.query(Support).filter_by(user_id=current_user.id, case_id=case_id).first()
    if existing_support:
        return jsonify({'error': 'locked'}), 200
    else:
        support = Support(user_id=current_user.id, case_id=case_id, side=side)
        db.session.add(support)
    db.session.commit()
    # 返回最新统计
    return api_support_counts(case_id)

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    c = db.session.query(Comment).get_or_404(comment_id)
    if c.author_id != current_user.id:
        flash('仅作者可删除评论', 'error')
        return redirect(url_for('case_detail', case_id=c.case_id))
    db.session.query(CommentLike).filter_by(comment_id=comment_id).delete()
    db.session.delete(c)
    db.session.commit()
    flash('评论已删除', 'success')
    return redirect(url_for('case_detail', case_id=c.case_id))

@app.route('/delete_evidence/<int:evidence_id>', methods=['POST'])
@login_required
def delete_evidence(evidence_id):
    e = db.session.query(Evidence).get_or_404(evidence_id)
    if e.submitter_id != current_user.id:
        flash('仅提交者可删除证据', 'error')
        return redirect(url_for('case_detail', case_id=e.case_id))
    db.session.query(EvidenceLike).filter_by(evidence_id=evidence_id).delete()
    db.session.query(EvidenceLegalNote).filter_by(evidence_id=evidence_id).delete()
    db.session.delete(e)
    db.session.commit()
    flash('证据已删除', 'success')
    return redirect(url_for('case_detail', case_id=e.case_id))

@app.route('/delete_case/<int:case_id>', methods=['POST'])
@login_required
def delete_case(case_id):
    case = db.session.query(Case).get_or_404(case_id)
    if case.initiator_id != current_user.id:
        flash('仅发起人可删除案件', 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    for e in list(case.evidences):
        db.session.query(EvidenceLike).filter_by(evidence_id=e.id).delete()
        db.session.query(EvidenceLegalNote).filter_by(evidence_id=e.id).delete()
        db.session.delete(e)
    for c in list(case.comments):
        db.session.query(CommentLike).filter_by(comment_id=c.id).delete()
        db.session.delete(c)
    for t in list(case.timeline):
        db.session.delete(t)
    ag = db.session.query(MediationAgreement).filter_by(case_id=case_id).first()
    if ag:
        for s in list(ag.signatures):
            db.session.delete(s)
        db.session.delete(ag)
    db.session.query(Support).filter_by(case_id=case_id).delete()
    db.session.delete(case)
    db.session.commit()
    flash('案件已删除', 'success')
    return redirect(url_for('index'))

# 静态服务上传的证据文件
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/generate_agreement/<int:case_id>', methods=['POST'])
@login_required
def generate_agreement(case_id):
    case = db.session.query(Case).get_or_404(case_id)
    
    # 检查权限
    if current_user.id != case.initiator_id and (not case.opponent_id or current_user.id != case.opponent_id):
        flash('只有案件当事人才可以生成调解协议', 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    
    # 检查是否已经存在协议
    existing_agreement = db.session.query(MediationAgreement).filter_by(case_id=case_id).first()
    if existing_agreement:
        flash('调解协议已存在', 'error')
        return redirect(url_for('case_detail', case_id=case_id))
    
    # 生成调解协议（AI智能总结案件事实）
    agreement_content = generate_mediation_agreement(case, case.initiator, case.opponent)
    
    # 创建协议记录 - 优化要求4：先不自动签署，需要双方确认案件事实
    agreement = MediationAgreement(
        case_id=case_id,
        content=agreement_content,
        initiator_signed=False,
        opponent_signed=False,
        initiator_confirmed=False,
        opponent_confirmed=False
    )
    db.session.add(agreement)
    
    # 添加时间线事件
    timeline_event = TimelineEvent(
        case_id=case_id,
        description=f'{current_user.username}生成了AI智能总结的调解协议'
    )
    db.session.add(timeline_event)
    
    db.session.commit()
    
    flash('调解协议生成成功，请双方确认案件事实后再签署', 'success')
    return redirect(url_for('case_detail', case_id=case_id))

# 更新调解协议内容（仅当事人在签署前可编辑，编辑后需重新确认）
@app.route('/update_agreement/<int:agreement_id>', methods=['POST'])
@login_required
def update_agreement(agreement_id):
    agreement = db.session.query(MediationAgreement).get_or_404(agreement_id)
    case = agreement.case

    # 权限校验：仅发起方或对峙方，当事人才可编辑
    is_initiator = current_user.id == case.initiator_id
    is_opponent = case.opponent_id and current_user.id == case.opponent_id
    if not (is_initiator or is_opponent):
        flash('仅案件当事人可以编辑调解协议', 'error')
        return redirect(url_for('case_detail', case_id=case.id))

    # 仅在双方未签署前允许编辑
    if agreement.initiator_signed or agreement.opponent_signed:
        flash('协议已签署，无法编辑', 'error')
        return redirect(url_for('case_detail', case_id=case.id))

    # 获取提交内容
    new_content = (request.form.get('content') or '').strip()
    if not new_content:
        flash('协议内容不能为空', 'error')
        return redirect(url_for('case_detail', case_id=case.id))

    # 对协议内容进行AI智能审核
    agreement_result = process_user_content(new_content, content_type='agreement', enable_privacy_masking=True)
    if not agreement_result['is_allowed']:
        violation_info = agreement_result.get('violation_info', {})
        severity = violation_info.get('severity', 'unknown')
        reason = violation_info.get('reason', '内容不符合规范')
        flash(f'协议内容包含违规信息（{severity}）: {reason}，请修改后重试', 'error')
        return redirect(url_for('case_detail', case_id=case.id))

    # 更新内容，并重置双方确认（需重新确认事实后才能签署）
    agreement.content = agreement_result['processed_content']  # 使用AI处理后的内容
    
    # 如果有用户提示信息，显示给用户
    if agreement_result.get('user_message'):
        flash(agreement_result['user_message'], 'info')
    agreement.initiator_confirmed = False
    agreement.opponent_confirmed = False

    # 添加时间线事件
    timeline_event = TimelineEvent(
        case_id=case.id,
        description=f'{current_user.username}编辑并更新了调解协议内容，需双方重新确认'
    )
    db.session.add(timeline_event)

    db.session.commit()

    flash('调解协议已更新，请双方重新确认案件事实', 'success')
    return redirect(url_for('case_detail', case_id=case.id))

@app.route('/sign_agreement/<int:agreement_id>', methods=['POST'])
@login_required
def sign_agreement(agreement_id):
    agreement = db.session.query(MediationAgreement).get_or_404(agreement_id)
    case = agreement.case
    
    # 检查权限
    is_initiator = current_user.id == case.initiator_id
    is_opponent = case.opponent_id and current_user.id == case.opponent_id
    
    if not is_initiator and not is_opponent:
        flash('您无权签署此调解协议', 'error')
        return redirect(url_for('case_detail', case_id=case.id))
    
    # 检查是否已确认案件事实（优化要求4）
    confirm_facts = 'confirm_facts' in request.form
    if not confirm_facts:
        flash('请先确认案件事实无误', 'error')
        return redirect(url_for('case_detail', case_id=case.id))
    
    # 可选：接收电子签名（base64图片）并保存
    signature_data = request.form.get('signature_data')
    saved_signature_path = None
    if signature_data and signature_data.startswith('data:image/png;base64,'):
        try:
            img_b64 = signature_data.split(',')[1]
            img_bytes = base64.b64decode(img_b64)
            # 保存到uploads/signatures/<case_id>/
            sig_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'signatures', str(case.id))
            os.makedirs(sig_dir, exist_ok=True)
            filename = f"{uuid.uuid4()}.png"
            file_path = os.path.join(sig_dir, filename)
            with open(file_path, 'wb') as f:
                f.write(img_bytes)
            # 存相对路径以便静态服务
            saved_signature_path = os.path.join('signatures', str(case.id), filename)
        except Exception as e:
            print(f"[Signature Save Error] {e}")
            saved_signature_path = None

    # 更新确认状态和签署状态
    if is_initiator:
        agreement.initiator_confirmed = True
        agreement.initiator_signed = True
        if saved_signature_path:
            sig = Signature(agreement_id=agreement.id, user_id=current_user.id, image_path=saved_signature_path)
            db.session.add(sig)
    elif is_opponent:
        agreement.opponent_confirmed = True
        agreement.opponent_signed = True
        if saved_signature_path:
            sig = Signature(agreement_id=agreement.id, user_id=current_user.id, image_path=saved_signature_path)
            db.session.add(sig)
    
    # 检查是否双方都已签署
    if agreement.initiator_signed and agreement.opponent_signed:
        case.status = 'settled'
        # 添加时间线事件
        timeline_event = TimelineEvent(
            case_id=case.id,
            description='双方已签署调解协议，案件已调解成功'
        )
        db.session.add(timeline_event)
    
    db.session.commit()
    
    flash('已确认案件事实并签署调解协议', 'success')
    return redirect(url_for('case_detail', case_id=case.id))

@app.route('/ai_content_test')
def ai_content_test():
    """AI内容预处理测试页面"""
    return render_template('ai_content_test.html')

if __name__ == '__main__':
    # 确保在应用上下文中创建数据库表
    try:
        with app.app_context():
            print('Creating database tables...')
            db.create_all()
            print('Database tables created successfully!')
            # 执行轻量级启动迁移，确保Comment新增列存在
            _safe_startup_migrations()
    except Exception as e:
        # 不阻断服务启动，打印错误以便诊断
        print('DB init create_all (in __main__) failed:', e)
    # 指定host参数
    port = int(os.getenv('PORT', '8001'))
    app.run(host='127.0.0.1', port=port, debug=False)

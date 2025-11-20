import os
from flask import Flask, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

def get_engine():
    db_url = os.getenv('DATABASE_URL') or os.getenv('POSTGRES_URL') or os.getenv('POSTGRES_URL_NON_POOLING')
    if not db_url:
        db_url = 'sqlite:////tmp/xiaohongshu_court.db'
    if db_url.startswith('postgres://'):
        db_url = 'postgresql://' + db_url[len('postgres://'):]
    return create_engine(db_url)

@app.route('/<int:evidence_id>', methods=['GET'])
def evidence_detail(evidence_id):
    engine = get_engine()
    with engine.connect() as conn:
        ev = conn.execute(text('SELECT id, case_id, submitter_id, content, file_path, evidence_type, created_at, is_key, is_proxy, likes, status FROM evidence WHERE id = :id'), {'id': evidence_id}).mappings().first()
        if not ev:
            return jsonify({'error': '证据不存在'}), 404
        submitter = conn.execute(text('SELECT username FROM user WHERE id = :uid'), {'uid': ev['submitter_id']}).mappings().first()
        return jsonify({
            'id': ev['id'],
            'case_id': ev['case_id'],
            'submitter_name': submitter['username'] if submitter else '未知用户',
            'submitter_id': ev['submitter_id'],
            'content': ev['content'],
            'file_path': ev['file_path'],
            'evidence_type': ev['evidence_type'],
            'created_at': str(ev['created_at']),
            'is_key': bool(ev['is_key']),
            'is_proxy': bool(ev['is_proxy']),
            'likes': ev['likes'],
            'status': ev['status']
        })
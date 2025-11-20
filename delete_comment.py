import os
from flask import Flask, request, jsonify
from sqlalchemy import create_engine, text

app = Flask(__name__)

def get_engine():
    db_url = os.getenv('DATABASE_URL') or os.getenv('POSTGRES_URL') or os.getenv('POSTGRES_URL_NON_POOLING')
    if not db_url:
        db_url = 'sqlite:////tmp/xiaohongshu_court.db'
    if db_url.startswith('postgres://'):
        db_url = 'postgresql://' + db_url[len('postgres://'):]
    return create_engine(db_url)

@app.route('/<int:comment_id>', methods=['POST'])
def delete_comment(comment_id):
    uid = request.headers.get('X-User-Id') or request.form.get('user_id')
    if not uid:
        return jsonify({'error': 'missing_user'}), 401
    engine = get_engine()
    with engine.begin() as conn:
        c = conn.execute(text('SELECT id, author_id, case_id FROM comment WHERE id = :id'), {'id': comment_id}).mappings().first()
        if not c:
            return jsonify({'error': 'not_found'}), 404
        if str(c['author_id']) != str(uid):
            return jsonify({'error': 'forbidden'}), 403
        conn.execute(text('DELETE FROM comment_like WHERE comment_id = :cid'), {'cid': comment_id})
        conn.execute(text('DELETE FROM comment WHERE id = :id'), {'id': comment_id})
    return jsonify({'ok': True})
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

@app.route('/<int:evidence_id>', methods=['POST'])
def delete_evidence(evidence_id):
    uid = request.headers.get('X-User-Id') or request.form.get('user_id')
    if not uid:
        return jsonify({'error': 'missing_user'}), 401
    engine = get_engine()
    with engine.begin() as conn:
        e = conn.execute(text('SELECT id, submitter_id, case_id FROM evidence WHERE id = :id'), {'id': evidence_id}).mappings().first()
        if not e:
            return jsonify({'error': 'not_found'}), 404
        if str(e['submitter_id']) != str(uid):
            return jsonify({'error': 'forbidden'}), 403
        conn.execute(text('DELETE FROM evidence_like WHERE evidence_id = :eid'), {'eid': evidence_id})
        conn.execute(text('DELETE FROM evidence_legal_note WHERE evidence_id = :eid'), {'eid': evidence_id})
        conn.execute(text('DELETE FROM evidence WHERE id = :id'), {'id': evidence_id})
    return jsonify({'ok': True})
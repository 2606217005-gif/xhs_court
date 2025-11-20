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

@app.route('/<int:case_id>', methods=['POST'])
def delete_case(case_id):
    uid = request.headers.get('X-User-Id') or request.form.get('user_id')
    if not uid:
        return jsonify({'error': 'missing_user'}), 401
    engine = get_engine()
    with engine.begin() as conn:
        case = conn.execute(text('SELECT id, initiator_id FROM case WHERE id = :id'), {'id': case_id}).mappings().first()
        if not case:
            return jsonify({'error': 'not_found'}), 404
        if str(case['initiator_id']) != str(uid):
            return jsonify({'error': 'forbidden'}), 403
        evs = conn.execute(text('SELECT id FROM evidence WHERE case_id = :cid'), {'cid': case_id}).mappings().all()
        for ev in evs:
            conn.execute(text('DELETE FROM evidence_like WHERE evidence_id = :eid'), {'eid': ev['id']})
            conn.execute(text('DELETE FROM evidence_legal_note WHERE evidence_id = :eid'), {'eid': ev['id']})
        cms = conn.execute(text('SELECT id FROM comment WHERE case_id = :cid'), {'cid': case_id}).mappings().all()
        for cm in cms:
            conn.execute(text('DELETE FROM comment_like WHERE comment_id = :cid'), {'cid': cm['id']})
        ag = conn.execute(text('SELECT id FROM mediation_agreement WHERE case_id = :cid'), {'cid': case_id}).mappings().first()
        if ag:
            conn.execute(text('DELETE FROM signature WHERE agreement_id = :aid'), {'aid': ag['id']})
            conn.execute(text('DELETE FROM mediation_agreement WHERE id = :aid'), {'aid': ag['id']})
        conn.execute(text('DELETE FROM support WHERE case_id = :cid'), {'cid': case_id})
        conn.execute(text('DELETE FROM timeline_event WHERE case_id = :cid'), {'cid': case_id})
        conn.execute(text('DELETE FROM evidence WHERE case_id = :cid'), {'cid': case_id})
        conn.execute(text('DELETE FROM comment WHERE case_id = :cid'), {'cid': case_id})
        conn.execute(text('DELETE FROM case WHERE id = :id'), {'id': case_id})
    return jsonify({'ok': True})
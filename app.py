from flask import Flask, render_template, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import uuid
import os
import sqlite3
from io import BytesIO
from crypto_utils import encrypt_data, decrypt_data

# ============================================================
# FIXED DATABASE PATH (project root, not instance/ folder)
# ============================================================
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, 'secrets.db')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + db_path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 51 * 1024 * 1024  # 51 MB

# ============================================================
# AUTO-FIX OLD SCHEMA
# If the existing DB has the old 'ciphertext' column, drop the
# tables so they can be recreated with the new schema.
# ============================================================
if os.path.exists(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(secrets)")
        cols = [c[1] for c in cursor.fetchall()]
        if cols and 'ciphertext' in cols:
            print("⚠️  Old schema detected – dropping tables to recreate.")
            cursor.execute("DROP TABLE IF EXISTS secrets")
            cursor.execute("DROP TABLE IF EXISTS attachments")
            conn.commit()
            print("✅ Old tables dropped.")
        conn.close()
    except Exception as e:
        print(f"⚠️  Schema check skipped: {e}")

db = SQLAlchemy(app)

# ============================================================
# MODELS
# ============================================================
class Secret(db.Model):
    __tablename__ = 'secrets'
    id = db.Column(db.String(8), primary_key=True)
    text_ciphertext = db.Column(db.Text, nullable=True)
    views_left = db.Column(db.Integer, default=1)
    has_password = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    attachments = db.relationship('Attachment', backref='secret', lazy=True, cascade='all, delete-orphan')

    def is_expired(self):
        return self.expires_at and self.expires_at < datetime.utcnow()

    def is_burned(self):
        return self.views_left <= 0

class Attachment(db.Model):
    __tablename__ = 'attachments'
    id = db.Column(db.Integer, primary_key=True)
    secret_id = db.Column(db.String(8), db.ForeignKey('secrets.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    content_type = db.Column(db.String(150), nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    size = db.Column(db.Integer, default=0)

# ============================================================
# CREATE TABLES
# ============================================================
with app.app_context():
    db.create_all()
    print(f"✅ Database ready at: {db_path}")

# ============================================================
# CLEANUP EXPIRED
# ============================================================
def cleanup_expired():
    now = datetime.utcnow()
    expired = Secret.query.filter(Secret.expires_at < now).all()
    for s in expired:
        db.session.delete(s)
    db.session.commit()

@app.before_request
def before_request():
    cleanup_expired()

# ============================================================
# ROUTES
# ============================================================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/create', methods=['POST'])
def create_secret():
    try:
        password = request.form.get('password', '')
        views = int(request.form.get('views', 1))
        expiry_hours = request.form.get('expiry', 'never')

        plaintext = request.form.get('text', '').strip()
        files = request.files.getlist('files')

        print(f"📥 Received: text len={len(plaintext)}, files={[f.filename for f in files]}")

        if len(files) > 3:
            return jsonify({'error': 'You can upload a maximum of 3 files.'}), 400

        total_size = 0
        file_data_list = []
        for file in files:
            if file and file.filename:
                data = file.read()
                total_size += len(data)
                if total_size > 50 * 1024 * 1024:
                    return jsonify({'error': 'Total file size must not exceed 50 MB.'}), 400
                file_data_list.append((file.filename, file.content_type or 'application/octet-stream', data))

        if not plaintext and not file_data_list:
            return jsonify({'error': 'Please enter text or select at least one file'}), 400

        text_ciphertext = None
        if plaintext:
            text_ciphertext = encrypt_data(plaintext.encode('utf-8'), password)

        secret_id = uuid.uuid4().hex[:8]

        expires_at = None
        if expiry_hours != 'never':
            hours = int(expiry_hours)
            expires_at = datetime.utcnow() + timedelta(hours=hours)

        secret = Secret(
            id=secret_id,
            text_ciphertext=text_ciphertext,
            views_left=views,
            has_password=bool(password),
            expires_at=expires_at
        )
        db.session.add(secret)
        db.session.commit()

        for filename, content_type, data in file_data_list:
            encrypted_data = encrypt_data(data, password)
            attachment = Attachment(
                secret_id=secret_id,
                filename=filename,
                content_type=content_type,
                ciphertext=encrypted_data,
                size=len(data)
            )
            db.session.add(attachment)

        db.session.commit()

        link = request.host_url + 's/' + secret_id
        if password:
            link += '#' + password

        return jsonify({
            'success': True,
            'link': link,
            'id': secret_id,
            'views': views,
            'expires': expiry_hours if expiry_hours != 'never' else 'Never',
            'has_text': bool(plaintext),
            'file_count': len(file_data_list),
            'password': password
        })

    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/s/<secret_id>')
def view_secret_page(secret_id):
    secret = Secret.query.get(secret_id)

    if not secret or secret.is_expired() or secret.is_burned():
        if secret:
            db.session.delete(secret)
            db.session.commit()
        return render_template('burned.html', message="This secret no longer exists."), 404

    has_text = secret.text_ciphertext is not None
    attachments = secret.attachments

    viewer_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if viewer_ip and ',' in viewer_ip:
        viewer_ip = viewer_ip.split(',')[0].strip()

    return render_template('view.html',
                         secret_id=secret_id,
                         has_password=secret.has_password,
                         has_text=has_text,
                         attachments=attachments,
                         viewer_ip=viewer_ip)

@app.route('/s/<secret_id>/decrypt_text', methods=['POST'])
def decrypt_text_route(secret_id):
    secret = Secret.query.get(secret_id)

    if not secret:
        return jsonify({'error': 'Secret not found'}), 404

    if secret.is_expired():
        db.session.delete(secret)
        db.session.commit()
        return jsonify({'error': 'Secret has expired'}), 410

    if secret.is_burned():
        db.session.delete(secret)
        db.session.commit()
        return jsonify({'error': 'Secret has already been destroyed'}), 410

    if secret.text_ciphertext is None:
        return jsonify({'error': 'No text attached'}), 404

    password = request.form.get('password', '')

    try:
        text_data = decrypt_data(secret.text_ciphertext, password)
    except ValueError:
        return jsonify({'error': 'Incorrect password'}), 401

    # Consume one view for the text
    secret.views_left -= 1
    if secret.views_left <= 0:
        db.session.delete(secret)
    db.session.commit()

    return jsonify({
        'success': True,
        'text': text_data.decode('utf-8')
    })

@app.route('/s/<secret_id>/decrypt_file/<int:attachment_id>', methods=['POST'])
def decrypt_file_route(secret_id, attachment_id):
    """
    Serves the file as inline content ONLY (no download).

    - `?preview=1` → thumbnail preview; does NOT consume a view
    - default      → full viewer; consumes one view and destroys the
                     secret once all views are used

    Supported preview types: images, audio, PDF, Word, text.
    (ZIP support has been removed.)
    """
    secret = Secret.query.get(secret_id)
    if not secret:
        return jsonify({'error': 'Secret not found'}), 404

    if secret.is_expired():
        db.session.delete(secret)
        db.session.commit()
        return jsonify({'error': 'Secret has expired'}), 410

    if secret.is_burned():
        db.session.delete(secret)
        db.session.commit()
        return jsonify({'error': 'Secret has already been destroyed'}), 410

    attachment = Attachment.query.filter_by(id=attachment_id, secret_id=secret_id).first()
    if not attachment:
        return jsonify({'error': 'Attachment not found'}), 404

    password = request.form.get('password', '')

    try:
        file_data = decrypt_data(attachment.ciphertext, password)
    except ValueError:
        return jsonify({'error': 'Incorrect password'}), 401

    # ✅ Whitelist (ZIP removed)
    ct = (attachment.content_type or '').lower()
    fname = (attachment.filename or '').lower()

    previewable = (
        ct.startswith('image/') or
        ct.startswith('audio/') or
        ct.startswith('text/') or
        ct == 'application/pdf' or
        ct in (
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ) or
        fname.endswith(('.doc', '.docx', '.pdf'))
    )
    if not previewable:
        return jsonify({'error': 'This file type cannot be previewed.'}), 403

    is_preview = request.args.get('preview', '0') == '1'

    # Consume a view only for the actual full-screen view
    if not is_preview:
        secret.views_left -= 1
        if secret.views_left <= 0:
            db.session.delete(secret)
        db.session.commit()

    # Force correct MIME type for Word so the browser handles it properly
    mimetype = ct
    if fname.endswith('.docx'):
        mimetype = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    elif fname.endswith('.doc'):
        mimetype = 'application/msword'

    return send_file(
        BytesIO(file_data),
        mimetype=mimetype,
        as_attachment=False,
        download_name=None
    )

# ============================================================
# ERROR HANDLERS
# ============================================================
@app.errorhandler(404)
def not_found(error):
    return render_template('burned.html', message="This secret does not exist."), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('burned.html', message="Something went wrong on our end."), 500

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'The uploaded files exceed the 50 MB limit.'}), 413

# ============================================================
# RUN
# ============================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
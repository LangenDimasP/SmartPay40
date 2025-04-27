# Tambahkan impor yang diperlukan di bagian atas
from flask import Flask, render_template, url_for, request, redirect, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_wtf.csrf import CSRFProtect
import qrcode
import logging
import io
from flask import session
import secrets
from datetime import date, datetime, time, timedelta
from sqlalchemy import func, or_ # Pastikan func dan or_ diimport
from sqlalchemy import or_
from flask import send_file
import math # Tambahkan import math jika belum ada di bagian atas
# Impor untuk Login Manager & UserMixin
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# Impor untuk Password Hashing
from werkzeug.utils import secure_filename # Untuk mengamankan nama file
import uuid # Untuk membuat nama file unik
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
import os # Digunakan untuk secret key

app = Flask(__name__)
csrf = CSRFProtect(app)
wib_tz = pytz.timezone("Asia/Jakarta")
utc_tz = pytz.timezone("UTC")

# === Konfigurasi Upload Foto Profil ===
# Tentukan path absolut ke folder statis
basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'static/profile_pics')
# Ekstensi file yang diizinkan
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Buat folder jika belum ada
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# ======================================

# === Fungsi Helper untuk Cek Ekstensi ===
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def format_rupiah(value):
    """Memformat angka menjadi string format Rupiah (Rp xxx.xxx)."""
    try:
        # Konversi ke float dulu untuk jaga-jaga
        val = float(value)
        # Cek apakah angka punya desimal yang relevan (lebih dari .00)
        # Gunakan toleransi kecil untuk masalah floating point
        if abs(val - round(val)) < 0.0001:
            # Jika bisa dianggap integer, format tanpa desimal
            # Gunakan f-string untuk format dengan pemisah ribuan (,) lalu ganti ke (.)
            formatted_value = f"{round(val):,}".replace(",", ".")
        else:
            # Jika punya desimal, format dengan 2 desimal, lalu tukar pemisah
            # Format dulu ke US (,) ribuan (.) desimal
            us_formatted = "{:,.2f}".format(val)
            # Tukar: Koma jadi TEMP, Titik jadi Koma, TEMP jadi Titik
            id_formatted = us_formatted.replace(",", "TEMP_SEP").replace(".", ",").replace("TEMP_SEP", ".")
            formatted_value = id_formatted

        return "Rp " + formatted_value
    except (ValueError, TypeError, OverflowError):
        # Jika input tidak valid (None, string non-angka, dll)
        return "Rp -" # Tampilkan strip atau format default lain
    
app.jinja_env.filters['rupiah'] = format_rupiah


try:
    # Untuk Python 3.9+ (built-in)
    from zoneinfo import ZoneInfo
except ImportError:
    # Fallback untuk Python < 3.9 (perlu install: pip install backports.zoneinfo)
    # Atau bisa pakai pytz: pip install pytz -> from pytz import timezone
    # Jika pakai pytz: ZoneInfo("Asia/Jakarta") -> timezone("Asia/Jakarta")
    # Jika pakai simple timedelta: hilangkan bagian zoneinfo, cukup tambah 7 jam
    # Untuk sekarang kita anggap Python 3.9+
     print("WARNING: zoneinfo module not found. Timezone features might be limited.")
     # Sediakan alternatif sederhana jika zoneinfo tidak ada
     class ZoneInfo: # Dummy class
         def __init__(self, key): pass

# ... (import lain, app, db, model, dll) ...

# === Fungsi Custom Filter untuk Format WIB ===
def format_wib(utc_dt):
    """Mengkonversi datetime UTC ke string format WIB."""
    if not utc_dt:
        return "-"  # Tampilkan strip jika data tidak ada
    try:
        utc_tz = pytz.timezone("UTC")
        wib_tz = pytz.timezone("Asia/Jakarta")
        utc_dt_aware = utc_dt.replace(tzinfo=utc_tz) if not utc_dt.tzinfo else utc_dt
        wib_dt = utc_dt_aware.astimezone(wib_tz)
        return wib_dt.strftime('%d %b %Y, %H:%M:%S') + " WIB"
    except Exception as e:
        print(f"Error formatting date {utc_dt} to WIB: {e}")
        try:
            wib_dt_fallback = utc_dt + timedelta(hours=7)
            return wib_dt_fallback.strftime('%d %b %Y, %H:%M:%S') + " WIB (Fallback)"
        except:
            return str(utc_dt) + " UTC (Error)"
# === Akhir Fungsi Custom Filter ===

# Registrasikan filter (SETELAH app = Flask(__name__) dan SETELAH definisi fungsi format_wib)
app.jinja_env.filters['wib'] = format_wib

# --- Secret Key (PENTING!) ---
# Dibutuhkan Flask untuk mengamankan session (data login) dan flash messages.
# Ganti 'isi-dengan-kunci-rahasia-super-aman-dan-unik' dengan string acak yang panjang.
# Di aplikasi nyata, ini tidak boleh ditulis langsung di kode.
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'isi-dengan-kunci-rahasia-super-aman-dan-unik')
# --------------------------

# --- Konfigurasi Database ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///kantin.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
# --------------------------

# --- Konfigurasi Flask-Login ---
login_manager = LoginManager()
login_manager.init_app(app)
# Jika pengguna mencoba akses halaman yang butuh login tapi belum login,
# mereka akan diarahkan ke halaman yang namanya 'login' (nama fungsi route login kita).
login_manager.login_view = 'login'
# Pesan flash yang akan ditampilkan saat pengguna diarahkan
login_manager.login_message = "Anda harus login untuk mengakses halaman ini."
login_manager.login_message_category = "warning" # Kategori pesan (untuk styling CSS nanti)
# --------------------------

# --- User Loader Callback ---
# Fungsi ini digunakan oleh Flask-Login untuk memuat user dari ID yang disimpan di session.
@login_manager.user_loader
def load_user(user_id):
    # Ambil user dari database berdasarkan ID
    return User.query.get(int(user_id))
# --------------------------

# --- Model Database (Update User) ---
# Tambahkan , UserMixin setelah db.Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False) # 'siswa', 'penjual', 'admin'
    balance = db.Column(db.Float, nullable=False, default=0.0)
    # === TAMBAHKAN DUA KOLOM BARU INI ===
    profile_pic_filename = db.Column(db.String(100), nullable=True, default=None) # Nama file foto profil
    kelas = db.Column(db.String(5), nullable=True)  # Untuk menyimpan 'X', 'XI', atau 'XII'
    jurusan = db.Column(db.String(10), nullable=True) # Untuk menyimpan 'RPL', 'DKV1', dll.
    is_active = db.Column(db.Boolean, nullable=False, default=True) # Defaultnya True (Aktif)
    # =====================================

    # Method set_password, check_password, __repr__ tetap sama
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} - {self.role}>'
    

# --- Class Transaction (TERPISAH dari User) ---
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    related_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    user_balance_before = db.Column(db.Float, nullable=False)
    user_balance_after = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=True)

    # Relasi
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('transactions', lazy='dynamic'))
    related_user = db.relationship('User', foreign_keys=[related_user_id])

    # ---> __repr__ untuk Transaction <---
    def __repr__(self):
        return f'<Transaction {self.id} ({self.type}) Rp {self.amount} for User {self.user_id}>'

    # Method untuk men-set password (otomatis hash)
    def set_password(self, password):
        # Membuat hash dari password yang diberikan
        self.password_hash = generate_password_hash(password)

    # Method untuk memeriksa apakah password yang diberikan cocok dengan hash
    def check_password(self, password):
        # Membandingkan password input dengan hash yang tersimpan
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username} - {self.role}>'
# --------------------------

class TopUpRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False) # Jumlah yg direquest
    request_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) # Waktu request dibuat
    status = db.Column(db.String(20), nullable=False, default='pending') # Status: 'pending', 'approved', 'rejected'
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # ID Admin yg menyetujui/menolak
    processed_timestamp = db.Column(db.DateTime, nullable=True) # Waktu request diproses admin

    # Relasi untuk memudahkan akses data student/admin
    student = db.relationship('User', foreign_keys=[student_id], backref=db.backref('topup_requests', lazy='dynamic'))
    admin = db.relationship('User', foreign_keys=[admin_id])

    def __repr__(self):
        # Representasi string objek (berguna untuk debugging)
        return f'<TopUpRequest {self.id} - Stud: {self.student_id} Amt: {self.amount} Stat: {self.status}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True) # Penerima notif
    message = db.Column(db.String(255), nullable=False) # Isi pesan notifikasi
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, index=True) # Waktu notif dibuat
    is_read = db.Column(db.Boolean, nullable=False, default=False) # Status dibaca (default: belum)
    related_link = db.Column(db.String(200), nullable=True) # Opsional: Link terkait notif (misal ke riwayat)

    # Relasi ke User (agar mudah akses user dari notif)
    user = db.relationship('User', backref=db.backref('notifications', lazy='dynamic', order_by='Notification.timestamp.desc()'))

    def __repr__(self):
        return f'<Notification {self.id} for User {self.user_id} - Read: {self.is_read}>'
    
# --- Routes (Halaman Web) ---
# (Route index tetap sama)
@app.route('/')
def index():
    return render_template('login.html')

# (Route login akan diupdate nanti)

# --- Route Registrasi ---


# --- Route Login (Update) ---
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@app.errorhandler(400)
def bad_request(e):
    logger.error(f"Bad Request: {e}")
    flash("Permintaan tidak valid. Silakan coba lagi.", "danger")
    return redirect(request.url), 400

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard_content'))
        elif current_user.role == 'penjual':
            return redirect(url_for('penjual_dashboard'))
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            if not user.is_active:
                flash('Akun Anda saat ini tidak aktif. Silakan hubungi admin.', 'danger')
                return redirect(url_for('login'))
            login_user(user)
            flash('Login berhasil! Selamat datang.', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard_content'))
            elif user.role == 'penjual':
                return redirect(url_for('penjual_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Login Gagal. Cek username dan password Anda.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/penjual/dashboard')
@login_required
def penjual_dashboard():
    if current_user.role != 'penjual':
        flash("Akses ditolak. Halaman ini hanya untuk penjual.", "danger")
        return redirect(url_for('dashboard'))

    # Zona Waktu WIB
    now_wib = datetime.now(wib_tz)
    today_wib = now_wib.date()
    today_wib_start_local = datetime.combine(today_wib, time.min).replace(tzinfo=wib_tz)
    tomorrow_wib_start_local = today_wib_start_local + timedelta(days=1)
    today_start_utc = today_wib_start_local.astimezone(utc_tz)
    tomorrow_start_utc = tomorrow_wib_start_local.astimezone(utc_tz)

    # Statistik Harian
    todays_earnings = 0.0
    todays_transaction_count = 0
    try:
        sum_result = db.session.query(func.sum(Transaction.amount)).filter(
            Transaction.related_user_id == current_user.id,
            Transaction.type == 'payment',
            Transaction.timestamp >= today_start_utc,
            Transaction.timestamp < tomorrow_start_utc
        ).scalar()
        if sum_result is not None:
            todays_earnings = float(sum_result)

        todays_transaction_count = Transaction.query.filter(
            Transaction.related_user_id == current_user.id,
            Transaction.type == 'payment',
            Transaction.timestamp >= today_start_utc,
            Transaction.timestamp < tomorrow_start_utc
        ).count()
    except Exception as e:
        print(f"Error calculating vendor stats: {e}")
        flash("Gagal memuat statistik harian.", "warning")

    # Transaksi Terbaru (3 transaksi)
    recent_transactions = Transaction.query.options(
        db.joinedload(Transaction.user)
    ).filter(
        Transaction.related_user_id == current_user.id,
        Transaction.type == 'payment'
    ).order_by(Transaction.timestamp.desc()).limit(3).all()

    # Jumlah Notifikasi Belum Dibaca (opsional, jika ada model Notification)
    unread_count = 0
    try:
        unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
    except Exception as e:
        print(f"Error fetching notifications for vendor {current_user.id}: {e}")

    # Data untuk Grafik (7 hari terakhir)
    chart_labels = []
    chart_data = []
    for i in range(6, -1, -1):
        day = today_wib - timedelta(days=i)
        chart_labels.append(day.strftime('%d %b'))
        start = datetime.combine(day, time.min).replace(tzinfo=wib_tz).astimezone(utc_tz)
        end = datetime.combine(day, time.max).replace(tzinfo=wib_tz).astimezone(utc_tz)
        sum_result = db.session.query(func.sum(Transaction.amount)).filter(
            Transaction.related_user_id == current_user.id,
            Transaction.type == 'payment',
            Transaction.timestamp >= start,
            Transaction.timestamp <= end
        ).scalar() or 0
        chart_data.append(float(sum_result))

    # Data untuk template
    data = {
        'qr_code_url': url_for('my_qr_code'),
        'balance': current_user.balance,
        'todays_earnings': todays_earnings,
        'todays_transaction_count': todays_transaction_count,
        'recent_transactions': recent_transactions,
        'unread_count': unread_count,
        'is_active': current_user.is_active,
        'chart_labels': chart_labels,
        'chart_data': chart_data
    }

    return render_template('penjual_dashboard.html', **data)


@app.route('/penjual/history')
@login_required
def history_vendor():
    if current_user.role != 'penjual':
        flash("Akses ditolak. Halaman ini hanya untuk penjual.", "danger")
        return redirect(url_for('dashboard'))

    # Parameter filter
    page = request.args.get('page', 1, type=int)
    per_page = 10
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    # Zona Waktu
    now_wib = datetime.now(wib_tz)
    today_wib = now_wib.date()
    default_start_dt = today_wib - timedelta(days=29)
    default_end_dt = today_wib

    # Parsing tanggal
    try:
        start_dt = date.fromisoformat(start_date_str) if start_date_str else default_start_dt
    except ValueError:
        start_dt = default_start_dt
    try:
        end_dt = date.fromisoformat(end_date_str) if end_date_str else default_end_dt
    except ValueError:
        end_dt = default_end_dt
    if start_dt > end_dt:
        start_dt, end_dt = default_start_dt, default_end_dt

    # Konversi ke UTC
    start_wib_day_local = datetime.combine(start_dt, time.min).replace(tzinfo=wib_tz)
    end_wib_day_local = datetime.combine(end_dt, time.max).replace(tzinfo=wib_tz)
    start_utc = start_wib_day_local.astimezone(utc_tz)
    end_utc = end_wib_day_local.astimezone(utc_tz)

    # Query transaksi
    query = Transaction.query.options(
        db.joinedload(Transaction.user)
    ).filter(
        Transaction.related_user_id == current_user.id,
        Transaction.type == 'payment',
        Transaction.timestamp >= start_utc,
        Transaction.timestamp <= end_utc
    )

    # Pagination
    transactions_pagination = query.order_by(Transaction.timestamp.desc()).paginate(page=page, per_page=per_page)

    return render_template(
        'penjual_history.html',
        transactions=transactions_pagination.items,
        pagination=transactions_pagination,
        filter_start_date=start_dt.strftime('%Y-%m-%d'),
        filter_end_date=end_dt.strftime('%Y-%m-%d')
    )

# --- Route Logout ---
@app.route('/logout')
@login_required # Decorator: hanya user yang sudah login bisa akses route ini
def logout():
    logout_user() # Fungsi dari Flask-Login untuk menghapus sesi user
    flash('Anda telah berhasil logout.', 'info')
    return redirect(url_for('index')) # Kembali ke halaman utama

# --- Route Dashboard ---
# Pastikan SEMUA import ini ada di bagian atas app.py
from flask import request, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from sqlalchemy import or_, func, and_ # Pastikan 'and_' juga diimport
from datetime import date, datetime, time, timedelta
try:
    from zoneinfo import ZoneInfo
except ImportError:
    # Fallback sederhana jika zoneinfo tidak ada
    from datetime import timezone, timedelta as ZoneInfo
    print("Warning: zoneinfo module not found, using simple timedelta fallback for WIB.")
    wib = None # Tandai bahwa zoneinfo tidak tersedia
else:
    try:
        wib = ZoneInfo("Asia/Jakarta")
    except Exception as e:
        print(f"Warning: Could not load Asia/Jakarta timezone: {e}")
        wib = None


# ... (kode app = Flask(), config, filter, login_manager, model lain, route lain) ...


@app.route('/dashboard')
@login_required
def dashboard():
    # Dapatkan waktu WIB saat ini
    now_wib = datetime.now(wib_tz)

    # === LOGIKA UNTUK SISWA ===
    if current_user.role == 'siswa':
        todays_spending = 0.0
        recent_transactions = []
        unread_count = 0
        recent_notifications = []

        try:
            # Kalkulasi Pengeluaran Harian
            today_wib = now_wib.date()
            today_wib_start_local = datetime.combine(today_wib, time.min).replace(tzinfo=wib_tz)
            tomorrow_wib_start_local = today_wib_start_local + timedelta(days=1)
            today_start_utc_for_calc = today_wib_start_local.astimezone(utc_tz)
            tomorrow_start_utc_for_calc = tomorrow_wib_start_local.astimezone(utc_tz)

            sum_result_spending = db.session.query(func.sum(Transaction.amount)).filter(
                Transaction.user_id == current_user.id,
                Transaction.type == 'payment',
                Transaction.timestamp >= today_start_utc_for_calc,
                Transaction.timestamp < tomorrow_start_utc_for_calc
            ).scalar()
            if sum_result_spending is not None:
                todays_spending = float(sum_result_spending)

            # Ambil 3 Transaksi Terbaru
            recent_transactions = Transaction.query.options(
                db.joinedload(Transaction.user),
                db.joinedload(Transaction.related_user)
            ).filter(
                or_(
                    Transaction.user_id == current_user.id,
                    and_(Transaction.related_user_id == current_user.id, Transaction.type == 'topup')
                )
            ).order_by(Transaction.timestamp.desc()).limit(3).all()

            # Ambil Data Notifikasi
            try:
                unread_count = Notification.query.filter_by(user_id=current_user.id, is_read=False).count()
                recent_notifications = current_user.notifications.limit(2).all()
            except Exception as notif_e:
                print(f"Error fetching notifications for student {current_user.id}: {notif_e}")

        except Exception as e:
            print(f"Error processing student dashboard data for {current_user.username}: {e}")
            flash("Gagal memuat data dashboard.", "warning")
            todays_spending = 0.0
            recent_transactions = []
            unread_count = 0
            recent_notifications = []

        # Render template siswa
        return render_template('/siswa/dashboard_siswa.html',
                               todays_spending=todays_spending,
                               recent_transactions=recent_transactions,
                               unread_count=unread_count,
                               recent_notifications=recent_notifications)

@app.route('/admin/topup', methods=['GET', 'POST'])
@login_required # Harus login
def admin_topup():
    # 1. Otorisasi: Pastikan yang akses adalah admin
    if current_user.role != 'admin':
        flash("Akses ditolak. Fitur ini hanya untuk admin.", "danger")
        return redirect(url_for('dashboard')) # Arahkan ke dashboard biasa

    if request.method == 'POST':
        user_id_to_topup = request.form.get('user_id')
        amount_str = request.form.get('amount')

        # 2. Validasi Input Server-side
        student = User.query.get(user_id_to_topup) # Cari user berdasarkan ID dari form
        amount = 0.0
        error_message = None

        if not student or student.role != 'siswa':
            error_message = "Siswa tidak ditemukan atau ID tidak valid."
        elif not amount_str:
            error_message = "Jumlah top up wajib diisi."
        else:
            try:
                amount = float(amount_str)
                if amount <= 0: # Atau bisa set minimum topup, misal amount < 100
                    error_message = "Jumlah top up harus lebih dari 0."
            except ValueError:
                error_message = "Jumlah top up harus berupa angka."

        # Jika ada error validasi
        if error_message:
            flash(error_message, "danger")
            # Kita perlu kirim lagi daftar siswa ke template saat render ulang form
            students = User.query.filter_by(role='siswa').order_by(User.username).all()
            return render_template('/admin/admin_topup.html', students=students)

        # 3. Proses Top Up (Jika Validasi Lolos)
        try:
            balance_before = student.balance
            student.balance += amount # Tambahkan saldo siswa
            balance_after = student.balance

            # 4. Buat Catatan Transaksi
            new_transaction = Transaction(
                user_id=current_user.id,         # <<< ID ADMIN yang melakukan Top Up
                related_user_id=student.id,    # <<< ID SISWA yang menerima Top Up
                type='topup',
                amount=amount,
                # user_balance_before/after tetap merujuk ke saldo siswa
                user_balance_before=balance_before, # Saldo siswa sebelum
                user_balance_after=balance_after,   # Saldo siswa sesudah
                description=f"Top up saldo untuk {student.username} oleh Admin" # Deskripsi lebih baik
            )
            db.session.add(new_transaction)
            db.session.commit()

            flash(f"Top up untuk {student.username} sebesar {format_rupiah(amount)} berhasil. Saldo baru: {format_rupiah(student.balance)}", "success")

        except Exception as e:
            db.session.rollback() # Batalkan jika ada error saat commit
            flash(f"Terjadi kesalahan saat proses top up: {str(e)}", "danger")

        # Arahkan kembali ke halaman top up setelah proses selesai (baik sukses/gagal)
        return redirect(url_for('admin_topup'))

    # --- Handle Method GET ---
    # Jika bukan POST, berarti user baru membuka halaman. Tampilkan form.
    # Ambil semua user dengan role 'siswa' untuk ditampilkan di dropdown
    students = User.query.filter_by(role='siswa').order_by(User.username).all()
    return render_template('/admin/admin_topup.html', students=students, active_page='admin_topup')

# --- Route untuk Admin Dashboard (Opsional tapi bagus) ---

@app.route('/admin/dashboard')
@login_required
def admin_dashboard_content():
    if current_user.role != 'admin':
        flash("Akses ditolak.", "danger")
        return redirect(url_for('dashboard'))

    # Statistik pengguna
    total_admins = User.query.filter_by(role='admin').count()
    total_vendors = User.query.filter_by(role='penjual').count()
    total_students = User.query.filter_by(role='siswa').count()
    active_vendors = User.query.filter_by(role='penjual', is_active=True).count()
    active_students = User.query.filter_by(role='siswa', is_active=True).count()

    # Statistik saldo
    total_student_balance = db.session.query(db.func.coalesce(db.func.sum(User.balance), 0)).filter_by(role='siswa', is_active=True).scalar()
    total_vendor_balance = db.session.query(db.func.coalesce(db.func.sum(User.balance), 0)).filter_by(role='penjual', is_active=True).scalar()

    # Statistik aktivitas hari ini
    today = datetime.utcnow().date()
    start_today = datetime.combine(today, datetime.min.time())
    end_today = datetime.combine(today, datetime.max.time())
    total_topups_today = db.session.query(db.func.coalesce(db.func.sum(Transaction.amount), 0))\
        .filter(Transaction.type == 'topup', Transaction.timestamp >= start_today, Transaction.timestamp <= end_today).scalar()
    total_payments_today = db.session.query(db.func.coalesce(db.func.sum(Transaction.amount), 0))\
        .filter(Transaction.type == 'payment', Transaction.timestamp >= start_today, Transaction.timestamp <= end_today).scalar()
    total_cashouts_today = db.session.query(db.func.coalesce(db.func.sum(Transaction.amount), 0))\
        .filter(Transaction.type == 'cashout_vendor', Transaction.timestamp >= start_today, Transaction.timestamp <= end_today).scalar()

    stats = {
        'total_admins': total_admins,
        'total_vendors': total_vendors,
        'total_students': total_students,
        'active_vendors': active_vendors,
        'active_students': active_students,
        'total_student_balance': total_student_balance,
        'total_vendor_balance': total_vendor_balance,
        'total_topups_today': total_topups_today,
        'total_payments_today': total_payments_today,
        'total_cashouts_today': total_cashouts_today
    }

    # Grafik aktivitas transaksi 7 hari terakhir
    today = datetime.utcnow().date()
    last_7_days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    chart_labels = []
    chart_topup = []
    chart_payment = []
    chart_cashout = []
    for d in last_7_days:
        start = datetime.combine(d, datetime.min.time())
        end = datetime.combine(d, datetime.max.time())
        chart_labels.append(d.strftime('%d %b'))
        chart_topup.append(Transaction.query.filter(Transaction.type == 'topup', Transaction.timestamp >= start, Transaction.timestamp <= end).count())
        chart_payment.append(Transaction.query.filter(Transaction.type == 'payment', Transaction.timestamp >= start, Transaction.timestamp <= end).count())
        chart_cashout.append(Transaction.query.filter(Transaction.type == 'cashout_vendor', Transaction.timestamp >= start, Transaction.timestamp <= end).count())

    return render_template(
        '/admin/dashboard_admin_content.html',
        stats=stats,
        chart_labels=chart_labels,
        chart_topup=chart_topup,
        chart_payment=chart_payment,
        chart_cashout=chart_cashout,
        now=datetime.utcnow(),
        active_page='admin_dashboard_content'
    )
@app.route('/pay', methods=['POST'])
@login_required # Harus login untuk bayar
def pay():
    # 1. Otorisasi: Pastikan yang bayar adalah siswa
    if current_user.role != 'siswa':
        flash("Hanya siswa yang dapat melakukan pembayaran.", "danger")
        return redirect(url_for('dashboard'))

    # 2. Ambil data dari form yang dikirim
    vendor_id = request.form.get('vendor_id')
    amount_str = request.form.get('amount')

    # 3. Validasi Input
    vendor = User.query.get(vendor_id) # Cari penjual berdasarkan ID
    amount = 0.0
    error_message = None # Variabel untuk menampung pesan error

    if not vendor or vendor.role != 'penjual':
        error_message = "Penjual yang dipilih tidak valid."
    elif not amount_str:
        error_message = "Jumlah pembayaran wajib diisi."
    else:
        try:
            amount = float(amount_str)
            if amount <= 0: # Harus positif
                error_message = "Jumlah pembayaran harus lebih dari 0."
        except ValueError:
            error_message = "Jumlah pembayaran harus berupa angka."

    # 4. Validasi Saldo: Cek apakah saldo siswa mencukupi
    # Lakukan ini HANYA jika validasi sebelumnya lolos (error_message masih None)
    if not error_message:
        if current_user.balance < amount:
            error_message = f"Saldo Anda tidak mencukupi! Saldo saat ini: Rp {'%.2f' % current_user.balance}"

    # Jika ada error dari validasi di atas, tampilkan pesan dan kembali ke dashboard
    if error_message:
        flash(error_message, "danger")
        return redirect(url_for('dashboard'))

    # 5. Proses Transaksi Database (Jika semua validasi lolos)
    try:
        # Catat saldo sebelum transfer
        student_balance_before = current_user.balance
        vendor_balance_before = vendor.balance # Saldo penjual sebelum

        # Lakukan transfer saldo
        current_user.balance -= amount
        vendor.balance += amount

        # Catat saldo siswa sesudah transfer
        student_balance_after = current_user.balance

        # 6. Buat record transaksi pembayaran
        payment_transaction = Transaction(
            user_id=current_user.id,         # ID Siswa yang membayar
            related_user_id=vendor.id,       # ID Penjual yang menerima
            type='payment',                  # Jenis transaksi
            amount=amount,                   # Jumlah yang dibayar
            user_balance_before=student_balance_before,
            user_balance_after=student_balance_after,
            description=f"Pembayaran ke penjual: {vendor.username}" # Deskripsi
        )
        db.session.add(payment_transaction) # Tambahkan transaksi ke sesi

        # (Opsional) Buat juga record transaksi dari sisi Penjual jika perlu detail di history penjual
        # vendor_transaction = Transaction(...) # type='penerimaan' atau sejenisnya
        # db.session.add(vendor_transaction)

        # Commit semua perubahan ke database (saldo siswa, saldo penjual, transaksi baru)
        # Ini penting dilakukan dalam satu blok try-commit agar atomik
        db.session.commit()

        flash(f"Pembayaran sebesar Rp {'%.2f' % amount} kepada {vendor.username} BERHASIL!", "success")

    except Exception as e:
        db.session.rollback() # Jika terjadi error saat commit, batalkan semua perubahan di sesi ini
        flash(f"GAGAL melakukan pembayaran: Terjadi kesalahan sistem. ({str(e)})", "danger")

    # Redirect kembali ke dashboard setelah selesai (sukses atau gagal)
    return redirect(url_for('dashboard'))

@app.route('/cashout', methods=['POST'])
@login_required
def cash_out():
    if current_user.role != 'penjual':
        flash("Hanya penjual yang dapat melakukan penarikan saldo.", "danger")
        return redirect(url_for('dashboard'))

    if current_user.balance <= 0:
        flash("Saldo Anda kosong, tidak ada yang bisa ditarik.", "warning")
        return redirect(url_for('penjual_dashboard'))

    admin_bank_mini = User.query.filter_by(role='admin').first()
    if not admin_bank_mini:
        flash("Kesalahan Sistem: Admin Bank Mini tidak ditemukan.", "danger")
        return redirect(url_for('penjual_dashboard'))

    amount_to_cash_out = current_user.balance
    try:
        vendor_balance_before = current_user.balance
        admin_balance_before = admin_bank_mini.balance

        current_user.balance = 0.0
        admin_bank_mini.balance += amount_to_cash_out

        cashout_transaction = Transaction(
            user_id=current_user.id,
            related_user_id=admin_bank_mini.id,
            type='cashout_vendor',
            amount=amount_to_cash_out,
            user_balance_before=vendor_balance_before,
            user_balance_after=0.0,
            description=f"Penarikan tunai oleh {current_user.username}"
        )
        db.session.add(cashout_transaction)
        db.session.commit()

        flash(f"Penarikan tunai sebesar {format_rupiah(amount_to_cash_out)} berhasil diproses!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Gagal melakukan penarikan tunai: {str(e)}", "danger")

    return redirect(url_for('penjual_dashboard'))

@app.route('/my_qr_code.png')
@login_required
def my_qr_code():
    # Hanya penjual yang boleh akses QR-nya sendiri
    if current_user.role != 'penjual':
        return "Akses ditolak", 403

    # Data yang ingin di-encode, misal ID user atau username
    data_to_encode = str(current_user.id)
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=8,
        border=4,
    )
    qr.add_data(data_to_encode)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    return send_file(img_io, mimetype='image/png')

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        flash("Akses ditolak. Halaman ini hanya untuk admin.", "danger")
        return redirect(url_for('dashboard'))

    # Ambil parameter filter dari URL
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Jumlah data per halaman
    filter_kelas = request.args.get('kelas')
    filter_jurusan = request.args.get('jurusan')
    filter_username = request.args.get('username')

    # Query dasar pengguna
    query = User.query

    # Filter berdasarkan kelas
    if filter_kelas:
        query = query.filter(User.kelas == filter_kelas)

    # Filter berdasarkan jurusan
    if filter_jurusan:
        query = query.filter(User.jurusan == filter_jurusan)

    # Filter berdasarkan nama pengguna
    if filter_username:
        query = query.filter(User.username.ilike(f"%{filter_username}%"))

    # Pagination
    users_pagination = query.order_by(User.id.asc()).paginate(page=page, per_page=per_page)

    return render_template(
        '/admin/admin_users.html',
        users=users_pagination.items,
        pagination=users_pagination,
        filter_kelas=filter_kelas,
        filter_jurusan=filter_jurusan,
        filter_username=filter_username, active_page='admin_users')

@app.route('/admin/transactions')
@login_required
def admin_transactions():
    if current_user.role != 'admin':
        flash("Akses ditolak. Halaman ini hanya untuk admin.", "danger")
        return redirect(url_for('dashboard'))

    # Ambil parameter filter dari URL
    page = request.args.get('page', 1, type=int)
    per_page = 8  # Jumlah data per halaman
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    filter_type = request.args.get('filter_type', 'all')
    username = request.args.get('username')

    # Query dasar transaksi
    query = Transaction.query

    # Filter berdasarkan tanggal
    if start_date:
        query = query.filter(Transaction.timestamp >= start_date)
    if end_date:
        query = query.filter(Transaction.timestamp <= end_date)

    # Filter berdasarkan tipe transaksi
    if filter_type != 'all':
        query = query.filter(Transaction.type == filter_type)

    # Filter berdasarkan username
    if username:
        query = query.join(User, Transaction.user_id == User.id).filter(User.username.ilike(f"%{username}%"))

    # Pagination
    transactions_pagination = query.order_by(Transaction.timestamp.desc()).paginate(page=page, per_page=per_page)

    return render_template(
        '/admin/admin_transactions.html',
        transactions=transactions_pagination.items,
        pagination=transactions_pagination,
        filter_start_date=start_date,
        filter_end_date=end_date,
        selected_type_filter=filter_type,
        filter_username=username, active_page='admin_transactions')

@app.route('/print/daily_summary')
@login_required
def print_daily_summary():
    # 1. Otorisasi: Pastikan yang akses adalah penjual
    if current_user.role != 'penjual':
        flash("Hanya penjual yang dapat mengakses fitur ini.", "danger")
        return redirect(url_for('dashboard'))

    # 2. Dapatkan Zona Waktu & Tanggal Hari Ini (WIB)
    try: wib = ZoneInfo("Asia/Jakarta")
    except Exception: wib = None
    now_wib = datetime.now(wib) if wib else datetime.utcnow() + timedelta(hours=7)
    today_wib = now_wib.date()

    # 3. Tentukan Batas Waktu UTC untuk Query Hari Ini (WIB)
    today_wib_start_local = datetime.combine(today_wib, time.min);
    if wib: today_wib_start_local = today_wib_start_local.replace(tzinfo=wib)
    tomorrow_wib_start_local = today_wib_start_local + timedelta(days=1)
    today_start_utc_for_calc = today_wib_start_local.astimezone(ZoneInfo("UTC")) if wib and isinstance(wib, ZoneInfo) else today_wib_start_local - timedelta(hours=7)
    tomorrow_start_utc_for_calc = tomorrow_wib_start_local.astimezone(ZoneInfo("UTC")) if wib and isinstance(wib, ZoneInfo) else tomorrow_wib_start_local - timedelta(hours=7)

    # 4. Hitung Total Pendapatan Hari Ini
    todays_earnings = 0.0
    try:
        sum_result = db.session.query(func.sum(Transaction.amount)).filter(
            Transaction.related_user_id == current_user.id,
            Transaction.type == 'payment',
            Transaction.timestamp >= today_start_utc_for_calc,
            Transaction.timestamp < tomorrow_start_utc_for_calc
        ).scalar()
        if sum_result is not None: todays_earnings = float(sum_result)
    except Exception as e:
        print(f"Error menghitung pendapatan harian untuk print: {e}")
        # Tetap lanjutkan meskipun gagal hitung total

    # 5. Ambil Daftar Transaksi Pembayaran Diterima Hari Ini
    daily_transactions = []
    try:
        daily_transactions = Transaction.query.options(
            db.joinedload(Transaction.user) # Load data siswa pembayar
        ).filter(
            Transaction.related_user_id == current_user.id, # Penjual sebagai penerima
            Transaction.type == 'payment',                  # Hanya pembayaran
            Transaction.timestamp >= today_start_utc_for_calc,
            Transaction.timestamp < tomorrow_start_utc_for_calc
        ).order_by(Transaction.timestamp.asc()).all() # Urutkan dari pagi ke sore
    except Exception as e:
         print(f"Error mengambil transaksi harian untuk print: {e}")
         flash("Gagal mengambil rincian transaksi untuk dicetak.", "warning")

    # 6. Siapkan data untuk dikirim ke template cetak
    report_data = {
        "vendor_name": current_user.username,
        # Format tanggal Indonesia yang bagus
        "report_date_str": today_wib.strftime('%A, %d %B %Y'),
        "total_earnings": todays_earnings,
        "transactions": daily_transactions,
        # Waktu saat laporan ini dibuat (sudah diformat WIB)
        "print_time_wib": format_wib(datetime.utcnow())
    }

    # 7. Render template khusus untuk cetak
    return render_template('vendor_daily_print.html', **report_data)

@app.route('/admin/users/toggle_active/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_active(user_id):
    # 1. Otorisasi: Pastikan hanya admin
    if current_user.role != 'admin':
        flash("Anda tidak memiliki izin untuk melakukan aksi ini.", "danger")
        # Arahkan ke dashboard biasa jika bukan admin mencoba akses
        return redirect(url_for('dashboard'))

    # 2. Cari user yang akan diubah statusnya
    # get_or_404 akan otomatis menampilkan halaman Not Found jika ID tidak ada
    user_to_toggle = User.query.get_or_404(user_id)

    # 3. Validasi: Admin tidak bisa menonaktifkan diri sendiri
    if user_to_toggle.id == current_user.id:
        flash("Anda tidak dapat mengubah status aktif akun Anda sendiri.", "warning")
        return redirect(url_for('admin_users'))

    # 4. Ubah status is_active
    try:
        # Balikkan statusnya (True jadi False, False jadi True)
        user_to_toggle.is_active = not user_to_toggle.is_active
        # Tentukan pesan berdasarkan status baru
        status_text = "diaktifkan" if user_to_toggle.is_active else "dinonaktifkan"
        # Simpan perubahan ke database
        db.session.commit()
        flash(f"Akun '{user_to_toggle.username}' berhasil {status_text}.", "success")
    except Exception as e:
        # Jika gagal simpan, batalkan perubahan
        db.session.rollback()
        flash(f"Gagal mengubah status akun: {str(e)}", "danger")

    # 5. Redirect kembali ke halaman daftar pengguna
    return redirect(url_for('admin_users'))

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def admin_edit_user(user_id):
    # Otorisasi Admin
    if current_user.role != 'admin':
        flash("Anda tidak memiliki izin.", "danger")
        return redirect(url_for('dashboard'))

    # Ambil data user yang mau diedit
    user_to_edit = User.query.get_or_404(user_id)

    # (Opsional) Cegah admin mengedit dirinya sendiri via halaman ini
    # if user_to_edit.id == current_user.id:
    #     flash("Gunakan halaman profil untuk mengedit data Anda sendiri.", "warning")
    #     return redirect(url_for('admin_users'))

    # Jika method POST (artinya form disubmit)
    if request.method == 'POST':
        # Ambil data baru dari form
        new_username = request.form.get('username').strip() # .strip() hapus spasi awal/akhir
        new_role = request.form.get('role') # Ambil role (akan None jika field disabled)
        new_kelas = request.form.get('kelas')
        new_jurusan = request.form.get('jurusan')

        # === Validasi Data Baru ===
        error = False
        # Cek field dasar
        if not new_username:
            flash("Username tidak boleh kosong.", "danger")
            error = True

        # Jika mencoba mengubah user yg bukan admin (role bisa diedit)
        if user_to_edit.role != 'admin':
            if not new_role or new_role not in ['siswa', 'penjual']:
                flash("Peran yang dipilih tidak valid.", "danger")
                error = True
        else:
            # Jika targetnya admin, pastikan rolenya tidak berubah
            new_role = 'admin' # Tetapkan kembali sebagai admin

        # Validasi Kelas/Jurusan jika rolenya siswa
        kelas_final = None
        jurusan_final = None
        if new_role == 'siswa':
            kelas_valid = ["X", "XI", "XII"]
            jurusan_valid = ["RPL", "DKV1", "DKV2", "AK", "MP", "BR"]
            if not new_kelas or new_kelas not in kelas_valid:
                flash("Pilihan Kelas untuk siswa tidak valid.", "danger")
                error = True
            if not new_jurusan or new_jurusan not in jurusan_valid:
                flash("Pilihan Jurusan untuk siswa tidak valid.", "danger")
                error = True
            kelas_final = new_kelas
            jurusan_final = new_jurusan
        # Jika role baru BUKAN siswa, otomatis set kelas/jurusan jadi None (kosong)

        # Cek keunikan username JIKA username diubah
        if new_username != user_to_edit.username:
            existing_user = User.query.filter(User.username == new_username, User.id != user_id).first()
            if existing_user:
                flash(f"Username '{new_username}' sudah digunakan.", "danger")
                error = True

        # Jika tidak ada error validasi, simpan perubahan
        if not error:
            try:
                user_to_edit.username = new_username
                user_to_edit.role = new_role
                user_to_edit.kelas = kelas_final # Akan None jika bukan siswa
                user_to_edit.jurusan = jurusan_final # Akan None jika bukan siswa
                db.session.commit()
                flash(f"Data pengguna '{new_username}' berhasil diperbarui.", "success")
                return redirect(url_for('admin_users')) # Kembali ke daftar pengguna
            except Exception as e:
                db.session.rollback()
                flash(f"Gagal memperbarui data: {str(e)}", "danger")
                # Tetap di halaman edit jika gagal simpan
        # Jika ada error validasi, template akan dirender ulang (lihat bawah)

    # Method GET (atau jika POST gagal validasi): Tampilkan form edit
    # Kirim data user yg diedit ke template agar form bisa terisi
    return render_template('admin_edit_users.html', user_to_edit=user_to_edit)

@app.route('/history')
@login_required
def history():
    # Pastikan hanya siswa
    if current_user.role != 'siswa':
        return redirect(url_for('dashboard'))

    # TODO: Salin dan sesuaikan query + filter transaksi dari fungsi dashboard lama
    # Query Sederhana Awal:
    transactions = Transaction.query.filter(
        or_(Transaction.user_id == current_user.id,
            and_(Transaction.related_user_id == current_user.id, Transaction.type == 'topup'))
    ).order_by(Transaction.timestamp.desc()).all()

    return render_template('history.html', transactions=transactions)

@app.route('/pay_vendor', methods=['GET', 'POST'])
@login_required
def pay_vendor():
    if current_user.role != 'siswa':
        logger.warning(f"Unauthorized access to /pay_vendor by user {current_user.username}, role: {current_user.role}")
        flash("Hanya siswa yang dapat mengakses halaman pembayaran.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        vendor_id = request.form.get('vendor_id')
        amount_str = request.form.get('amount')
        logger.debug(f"Processing payment: vendor_id={vendor_id}, amount={amount_str}")
        
        vendor = User.query.get(vendor_id)
        amount = 0.0
        error_message = None

        # --- Validasi Input ---
        if not vendor or vendor.role != 'penjual':
            error_message = "Penjual tidak valid atau tidak ditemukan."
        elif not amount_str:
            error_message = "Jumlah pembayaran wajib diisi."
        else:
            try:
                amount = float(amount_str)
                if amount <= 0:
                    error_message = "Jumlah pembayaran harus positif."
            except ValueError:
                error_message = "Jumlah pembayaran harus berupa angka."

        # --- Validasi Saldo ---
        if not error_message:
            # Refresh data user untuk saldo terbaru sebelum cek
            db.session.refresh(current_user)
            if current_user.balance < amount:
                error_message = f"Saldo Anda tidak mencukupi! Saldo saat ini: {format_rupiah(current_user.balance)}"

        # --- Handle jika ada error validasi ---
        if error_message:
            logger.warning(f"Payment validation failed: {error_message}")
            flash(error_message, "danger")
            vendors = User.query.filter_by(role='penjual', is_active=True).order_by(User.username).all()
            return render_template('/siswa/pay_vendor.html', vendors=vendors)

        # --- Proses Transaksi & Notifikasi ---
        try:
            # Ambil saldo sebelum
            student_balance_before = current_user.balance
            vendor_balance_before = vendor.balance

            # Update saldo
            current_user.balance -= amount
            vendor.balance += amount
            student_balance_after = current_user.balance

            # 1. Add Transaksi Pembayaran ke session
            payment_transaction = Transaction(
                user_id=current_user.id,
                related_user_id=vendor.id,
                type='payment',
                amount=amount,
                user_balance_before=student_balance_before,
                user_balance_after=student_balance_after,
                description=f"Pembayaran ke penjual: {vendor.username}"
            )
            db.session.add(payment_transaction)

            # 2. Add Notifikasi Pembayaran ke session
            notif_message = f"Pembayaran sebesar {format_rupiah(amount)} ke {vendor.username} berhasil."
            new_notif = Notification(user_id=current_user.id, message=notif_message)
            db.session.add(new_notif)

            # 3. Commit SEMUA perubahan sekaligus
            db.session.commit()
            logger.info(f"Payment successful: user={current_user.username}, vendor={vendor.username}, amount={amount}")

            # Flash pesan sukses
            flash(f"Pembayaran sebesar {format_rupiah(amount)} kepada {vendor.username} BERHASIL!", "success")
            return redirect(url_for('dashboard'))

        except Exception as e:
            db.session.rollback()
            logger.error(f"Error processing payment for user {current_user.username}: {e}")
            flash("GAGAL melakukan pembayaran: Terjadi kesalahan sistem.", "danger")
            return redirect(url_for('pay_vendor'))

    # --- Method GET ---
    else:
        vendors = User.query.filter_by(role='penjual', is_active=True).order_by(User.username).all()
        logger.debug(f"Rendering /siswa/pay_vendor.html with {len(vendors)} vendors")
        return render_template('/siswa/pay_vendor.html', vendors=vendors)
    

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # Proses upload jika method POST
    if request.method == 'POST':
        # Cek apakah ada file di request
        if 'profile_pic' not in request.files:
            flash('Tidak ada bagian file.', 'warning')
            return redirect(request.url) # Kembali ke profile page
        file = request.files['profile_pic']
        # Jika user tidak pilih file, browser mungkin submit empty part
        if file.filename == '':
            flash('Tidak ada file yang dipilih.', 'warning')
            return redirect(request.url)

        # Jika file ada dan valid
        if file and allowed_file(file.filename): # Pastikan fungsi allowed_file() ada
            # Buat nama file aman dan unik
            filename_secure = secure_filename(file.filename)
            ext = filename_secure.rsplit('.', 1)[1].lower()
            unique_filename = f"{current_user.id}_{uuid.uuid4().hex}.{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename) # Pastikan UPLOAD_FOLDER dikonfig

            try:
                # Hapus file lama jika ada
                if current_user.profile_pic_filename:
                     old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.profile_pic_filename)
                     if os.path.exists(old_file_path):
                         os.remove(old_file_path)
                         print(f"Deleted old profile pic: {old_file_path}")

                # Simpan file baru
                file.save(file_path)
                print(f"Saved new profile pic: {file_path}")

                # Update nama file di database user
                current_user.profile_pic_filename = unique_filename
                db.session.commit()
                flash('Foto profil berhasil diperbarui!', 'success')

            except Exception as e:
                db.session.rollback()
                print(f"Error saving file or updating db: {e}")
                flash('Terjadi kesalahan saat mengupload foto.', 'danger')

            return redirect(url_for('profile')) # Redirect kembali ke halaman profil
        else:
            flash('Tipe file tidak diizinkan (hanya .png, .jpg, .jpeg, .gif).', 'danger')
            return redirect(request.url)

    # Method GET: tampilkan halaman profil
    # current_user otomatis tersedia via Flask-Login
    # Pastikan template 'profile.html' sudah ada
    return render_template('/siswa/profile.html')

@app.route('/riwayat_siswa') # Nama route baru
@login_required
def riwayat_siswa(): # Nama fungsi baru
    # Pastikan hanya siswa
    if current_user.role != 'siswa':
        flash("Halaman ini hanya untuk siswa.", "danger")
        return redirect(url_for('dashboard'))

    # --- Ambil & Proses Filter ---
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')
    selected_type_filter = request.args.get('filter_type', 'all') # Default 'all'

    # Zona Waktu & Tanggal Default (misal: 30 hari terakhir)
    try: wib = ZoneInfo("Asia/Jakarta")
    except Exception: wib = None
    now_wib = datetime.now(wib) if wib and isinstance(wib, ZoneInfo) else datetime.utcnow() + timedelta(hours=7)
    today_wib = now_wib.date()
    default_start_dt = today_wib - timedelta(days=29) # Default 30 hari
    default_end_dt = today_wib

    # Parsing tanggal input
    try: start_dt = date.fromisoformat(start_date_str) if start_date_str else default_start_dt
    except ValueError: start_dt = default_start_dt
    try: end_dt = date.fromisoformat(end_date_str) if end_date_str else default_end_dt
    except ValueError: end_dt = default_end_dt
    if start_dt > end_dt: start_dt, end_dt = default_start_dt, default_end_dt # Reset jika tidak valid

    # Konversi ke batas UTC untuk query (Awal hari start -> Akhir hari end)
    start_wib_day_local = datetime.combine(start_dt, time.min);
    if wib and isinstance(wib, ZoneInfo): start_wib_day_local = start_wib_day_local.replace(tzinfo=wib)
    end_wib_day_local = datetime.combine(end_dt, time.max)
    if wib and isinstance(wib, ZoneInfo): end_wib_day_local = end_wib_day_local.replace(tzinfo=wib)
    start_utc_for_query = start_wib_day_local.astimezone(ZoneInfo("UTC")) if wib and isinstance(wib, ZoneInfo) else start_wib_day_local - timedelta(hours=7)
    end_utc_for_query = end_wib_day_local.astimezone(ZoneInfo("UTC")) if wib and isinstance(wib, ZoneInfo) else end_wib_day_local - timedelta(hours=7)

    # --- Query Transaksi Siswa dengan Filter ---
    base_query = Transaction.query.options(
        db.joinedload(Transaction.user), db.joinedload(Transaction.related_user)
    ).filter(
        or_( # Transaksi yg dia lakukan ATAU topup yg dia terima
            Transaction.user_id == current_user.id,
            and_(Transaction.related_user_id == current_user.id, Transaction.type == 'topup')
        )
    ).filter( # Filter tanggal
        Transaction.timestamp >= start_utc_for_query,
        Transaction.timestamp <= end_utc_for_query
    )

    # Filter Tipe (jika bukan 'all')
    if selected_type_filter == 'payment':
        base_query = base_query.filter(Transaction.user_id == current_user.id, Transaction.type == 'payment')
    elif selected_type_filter == 'topup':
        base_query = base_query.filter(Transaction.related_user_id == current_user.id, Transaction.type == 'topup')

    # Ambil semua hasil, urutkan terbaru di atas
    # TODO: Implementasi Pagination jika data sangat banyak
    transactions = base_query.order_by(Transaction.timestamp.desc()).all()

    # Render template baru 'transaksi_siswa.html'
    return render_template('/siswa/transaksi_siswa.html',
                           transactions=transactions,
                           filter_start_date=start_dt.strftime('%Y-%m-%d'),
                           filter_end_date=end_dt.strftime('%Y-%m-%d'),
                           selected_type_filter=selected_type_filter)
# === Akhir Route Profil ===

@app.route('/request_topup', methods=['GET', 'POST'])
@login_required
def request_topup():
    # Pastikan hanya siswa
    if current_user.role != 'siswa':
        flash("Hanya siswa yang dapat membuat request top up.", "danger")
        return redirect(url_for('dashboard'))

    # Cek apakah siswa ini sudah punya request yang statusnya 'pending'
    pending_request = TopUpRequest.query.filter_by(student_id=current_user.id, status='pending').first()

    # Proses form jika method POST
    if request.method == 'POST':
        print(f"Received POST request to /request_topup from user {current_user.id}: {request.form}")  # Logging untuk debug

        # Jika sudah ada pending, jangan izinkan buat request baru
        if pending_request:
            flash('Anda sudah memiliki 1 request top up yang belum diproses. Harap selesaikan pembayaran tunai di Bank Mini dahulu.', 'warning')
            return redirect(url_for('request_topup'))

        # Ambil jumlah dari form
        amount_str = request.form.get('amount')
        amount = 0.0
        error = False

        if not amount_str:
            print("Error: Amount is missing in form data")
            flash('Jumlah request top up wajib diisi.', 'danger')
            error = True
        else:
            try:
                amount = float(amount_str)
                # Validasi jumlah minimum request, misal 1000
                if amount < 1000:
                    print(f"Error: Amount {amount} is below minimum 1000")
                    flash('Jumlah minimum request top up adalah Rp 1.000.', 'danger')
                    error = True
            except ValueError:
                print(f"Error: Invalid amount format: {amount_str}")
                flash('Jumlah harus berupa angka.', 'danger')
                error = True

        # Jika validasi lolos
        if not error:
            try:
                # Buat record request baru
                new_request = TopUpRequest(
                    student_id=current_user.id,
                    amount=amount,
                    status='pending',
                    request_timestamp=datetime.now(pytz.timezone("UTC"))
                )
                db.session.add(new_request)
                db.session.commit()
                print(f"Top-up request created: {amount} for user {current_user.id}")
                flash(f'Request top up sebesar {format_rupiah(amount)} berhasil dibuat. Silakan lakukan pembayaran tunai sejumlah tersebut di Bank Mini.', 'success')
                return redirect(url_for('request_topup'))
            except Exception as e:
                db.session.rollback()
                print(f"Error creating top-up request for user {current_user.id}: {e}")
                flash('Gagal membuat request top up, silakan coba lagi.', 'danger')
                return redirect(url_for('request_topup'))

        # Jika validasi gagal, redirect kembali ke GET request
        print("Validation failed, redirecting to GET /request_topup")
        return redirect(url_for('request_topup'))

    # Method GET: Tampilkan form dan riwayat request
    else:
        # Ambil juga beberapa request terakhir (misal 5) untuk ditampilkan
        recent_requests = TopUpRequest.query.filter_by(student_id=current_user.id)\
                                           .order_by(TopUpRequest.request_timestamp.desc())\
                                           .limit(5).all()

        return render_template('/siswa/topup_siswa.html',
                               pending_request=pending_request,
                               recent_requests=recent_requests)
# ==========================================

@app.route('/admin/pending_topups')
@login_required
def admin_pending_topups():
    # Otorisasi: Pastikan hanya admin
    if current_user.role != 'admin':
        flash("Akses ditolak. Fitur ini hanya untuk admin.", "danger")
        return redirect(url_for('dashboard'))

    try:
        # Ambil semua data TopUpRequest yang statusnya 'pending'
        # Sekaligus ambil data siswa terkait (joinedload untuk efisiensi)
        # Urutkan berdasarkan request paling lama (ascending)
        pending_requests = TopUpRequest.query.options(
            db.joinedload(TopUpRequest.student) # Eager load data siswa
        ).filter_by(status='pending').order_by(TopUpRequest.request_timestamp.asc()).all()
    except Exception as e:
         print(f"Error mengambil request topup pending: {e}")
         flash("Gagal memuat daftar request top up.", "danger")
         pending_requests = [] # List kosong jika error

    # Render template baru, kirim data request pending
    return render_template('/admin/admin_pending_topups.html', requests=pending_requests, active_page='admin_pending_topups')

@app.route('/admin/approve_topup/<int:request_id>', methods=['POST'])
@login_required
def admin_approve_topup(request_id):
    # 1. Otorisasi: Pastikan hanya admin
    if current_user.role != 'admin':
        logger.warning(f"Unauthorized access to /admin/approve_topup/{request_id} by user {current_user.username}")
        flash("Anda tidak memiliki izin.", "danger")
        return redirect(url_for('dashboard'))

    # 2. Cari request top up berdasarkan ID
    topup_request = TopUpRequest.query.get_or_404(request_id)
    logger.debug(f"Processing top-up request ID {request_id}, status: {topup_request.status}")

    # 3. Validasi Status: Pastikan masih 'pending'
    if topup_request.status != 'pending':
        logger.info(f"Top-up request ID {request_id} already processed, status: {topup_request.status}")
        flash(f"Request top up ini sudah diproses sebelumnya (Status: {topup_request.status}).", "warning")
        return redirect(url_for('admin_pending_topups'))

    # 4. Cari data siswa
    student = User.query.get(topup_request.student_id)
    if not student:
        logger.error(f"Student not found for top-up request ID {request_id}")
        flash(f"Data siswa untuk request ID {request_id} tidak ditemukan.", "danger")
        return redirect(url_for('admin_pending_topups'))

    # 5. Proses Inti: Update Saldo, Buat Transaksi, Update Request, Buat Notifikasi
    try:
        amount_to_add = topup_request.amount
        balance_before = student.balance
        student.balance += amount_to_add  # Tambah saldo siswa
        balance_after = student.balance

        # Buat record transaksi 'topup'
        new_transaction = Transaction(
            user_id=current_user.id,        # ID Admin
            related_user_id=student.id,     # ID Siswa
            type='topup',
            amount=amount_to_add,
            user_balance_before=balance_before,
            user_balance_after=balance_after,
            description=f"Persetujuan Request Top Up ID: {topup_request.id}"
        )
        db.session.add(new_transaction)

        # Update status record TopUpRequest
        topup_request.status = 'approved'
        topup_request.admin_id = current_user.id
        topup_request.processed_timestamp = datetime.utcnow()
        db.session.add(topup_request)

        # Buat Notifikasi untuk Siswa
        notif_message = f"Top up sebesar {format_rupiah(amount_to_add)} telah disetujui oleh admin."
        new_notif = Notification(user_id=student.id, message=notif_message)
        db.session.add(new_notif)

        # Commit semua perubahan
        db.session.commit()
        logger.info(f"Top-up request ID {request_id} approved for student {student.username}, amount: {amount_to_add}")

        # Beri pesan sukses
        flash(f"Request Top Up untuk {student.username} sebesar {format_rupiah(amount_to_add)} berhasil disetujui.", "success")

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error approving top-up request ID {request_id}: {e}")
        flash("GAGAL menyetujui request top up: Terjadi kesalahan sistem.", "danger")

    return redirect(url_for('admin_pending_topups'))

# === Akhir Fungsi Route Approve Top Up ===

@app.route('/notifications/mark_read', methods=['POST'])
@login_required
def mark_notifications_read():
    # Hanya user yg login yg bisa tandai notifnya sendiri
    if not current_user.is_authenticated:
        return jsonify(success=False, message="User not logged in"), 401

    try:
        # Cari semua notifikasi milik user ini yang belum dibaca
        unread_notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()

        # Jika ada yang belum dibaca, ubah statusnya
        if unread_notifications:
            for notif in unread_notifications:
                notif.is_read = True
            # Commit perubahan ke database
            db.session.commit()
            print(f"Marked {len(unread_notifications)} notifications as read for user {current_user.id}")
        else:
             print(f"No unread notifications to mark as read for user {current_user.id}")

        # Kirim response sukses ke Javascript
        return jsonify(success=True)

    except Exception as e:
        db.session.rollback()
        print(f"Error marking notifications as read for user {current_user.id}: {e}")
        # Kirim response gagal ke Javascript
        return jsonify(success=False, message="Gagal update status notifikasi"), 500
# =================================================

@app.route('/detail_notif')
@login_required
def detail_notif():
    # Pastikan hanya siswa
    if current_user.role != 'siswa':
        flash("Halaman ini hanya untuk siswa.", "danger")
        return redirect(url_for('dashboard'))

    # Ambil SEMUA notifikasi user ini (sudah diurut terbaru di atas oleh backref)
    all_notifications = current_user.notifications.all()

    # Tandai SEMUA notifikasi sebagai sudah dibaca saat halaman ini dibuka
    # (Alternatif selain mark on open panel)
    # try:
    #     unread = Notification.query.filter_by(user_id=current_user.id, is_read=False).all()
    #     if unread:
    #         for n in unread:
    #             n.is_read = True
    #         db.session.commit()
    # except Exception as e:
    #     db.session.rollback()
    #     print(f"Error marking all as read on detail page: {e}")

    return render_template('/siswa/detail_notif.html', notifications=all_notifications)
    # === BARU: Model untuk Notifikasi Pengguna ===

@app.route('/admin/register_user', methods=['GET', 'POST'])
@login_required
def admin_register_user():
    # Hanya admin yang boleh akses
    if current_user.role != 'admin':
        flash("Hanya admin yang dapat mendaftarkan akun baru.", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        kelas = request.form.get('kelas')
        jurusan = request.form.get('jurusan')

        error = False
        # Validasi dasar
        if not username or not password or not confirm_password or not role:
            flash('Semua kolom wajib diisi!', 'danger')
            error = True
        if password != confirm_password:
            flash('Password dan konfirmasi password tidak cocok!', 'danger')
            error = True
        if role not in ['siswa', 'penjual']:
            flash('Peran yang dipilih tidak valid.', 'danger')
            error = True

        # Validasi kelas/jurusan jika siswa
        if role == 'siswa':
            kelas_valid = ["X", "XI", "XII"]
            jurusan_valid = ["RPL", "DKV1", "DKV2", "AK", "MP", "BR"]
            if not kelas or not jurusan:
                flash('Siswa wajib memilih Kelas dan Jurusan!', 'danger')
                error = True
            if kelas not in kelas_valid:
                flash('Kelas yang dipilih tidak valid.', 'danger')
                error = True
            if jurusan not in jurusan_valid:
                flash('Jurusan yang dipilih tidak valid.', 'danger')
                error = True

        # Cek username unik
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username ini sudah digunakan, silakan pilih username lain.', 'warning')
            error = True

        if error:
            return redirect(url_for('admin_register_user'))

        # Buat user baru
        user_data = {
            'username': username,
            'role': role
        }
        if role == 'siswa':
            user_data['kelas'] = kelas
            user_data['jurusan'] = jurusan

        new_user = User(**user_data)
        new_user.set_password(password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash(f'Akun {username} ({role}) berhasil dibuat!', 'success')
            return redirect(url_for('admin_users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan saat membuat akun: {str(e)}', 'danger')
            return redirect(url_for('admin_register_user'))

    # Method GET: tampilkan form
    return render_template('/admin/admin_register_user.html', active_page='admin_register_user')


# !!! PENTING: Hapus atau komentari route @app.route('/pay', methods=['POST']) yang lama
# karena logikanya akan dipindah ke /pay_vendor !!!
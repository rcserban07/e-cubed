"""
E-Cubed Security System
Enterprise access control dashboard with role-based auth,
real-time location tracking, and comprehensive access logging.
"""

import os
import io
import csv
import base64
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import pyotp
import qrcode
from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify,
    abort,
    session,
    Response,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, SelectField, SubmitField, EmailField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional


def _env_bool(name: str, default: bool) -> bool:
    """Parse a boolean env var, tolerant of true/false/1/0/yes/no."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# App factory & config
# ---------------------------------------------------------------------------

load_dotenv()

DEBUG = _env_bool("FLASK_DEBUG", False)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///ecube.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["WTF_CSRF_TIME_LIMIT"] = 3600  # 1 hour

# Session cookie hardening. SESSION_COOKIE_SECURE defaults on since browsers
# require it for Geolocation anyway (see README's ngrok/HTTPS note) — flip
# SESSION_COOKIE_SECURE=false in .env only for plain-http local testing.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = _env_bool("SESSION_COOKIE_SECURE", True)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
socketio = SocketIO(app, cors_allowed_origins=os.getenv("SOCKETIO_CORS_ORIGINS", "*"))
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "warning"
limiter = Limiter(get_remote_address, app=app, default_limits=[])

# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    role = db.Column(
        db.String(20), nullable=False, default="employee"
    )  # admin | employee
    is_active_user = db.Column(db.Boolean, default=True)
    totp_secret = db.Column(db.String(32), nullable=True)  # Base32-encoded secret
    totp_enabled = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    # Relationships
    access_logs = db.relationship("AccessLog", backref="user", lazy="dynamic")
    locations = db.relationship("Location", backref="user", lazy="dynamic")

    def set_password(self, password: str):
        self.password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(
            password.encode("utf-8"), self.password_hash.encode("utf-8")
        )

    def generate_totp_secret(self):
        """Generate a new TOTP secret for this user."""
        self.totp_secret = pyotp.random_base32()
        self.totp_enabled = False  # Not enabled until verified

    def get_totp_uri(self):
        """Get the otpauth URI for QR code generation."""
        if not self.totp_secret:
            return None
        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(name=self.username, issuer_name="E-Cubed Security")

    def verify_totp(self, token: str) -> bool:
        """Verify a TOTP token (allows 1 window of drift)."""
        if not self.totp_secret:
            return False
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token, valid_window=1)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


class AccessLog(db.Model):
    __tablename__ = "access_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    event_type = db.Column(
        db.String(50), nullable=False
    )  # login | logout | access_granted | access_denied
    detail = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    timestamp = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )

    def __repr__(self):
        return f"<AccessLog {self.event_type} user={self.user_id} @ {self.timestamp}>"


class Location(db.Model):
    __tablename__ = "locations"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    accuracy = db.Column(db.Float, nullable=True)  # metres
    timestamp = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc), index=True
    )

    def __repr__(self):
        return f"<Location user={self.user_id} ({self.latitude}, {self.longitude})>"


# ---------------------------------------------------------------------------
# Forms
# ---------------------------------------------------------------------------


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign In")


class RegisterUserForm(FlaskForm):
    username = StringField(
        "Username", validators=[DataRequired(), Length(min=3, max=80)]
    )
    name = StringField("Full Name", validators=[DataRequired(), Length(max=120)])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone", validators=[Optional(), Length(max=20)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    role = SelectField(
        "Role",
        choices=[("employee", "Employee"), ("admin", "Admin")],
        validators=[DataRequired()],
    )
    submit = SubmitField("Register")


class UpdateUserForm(FlaskForm):
    name = StringField("Full Name", validators=[DataRequired(), Length(max=120)])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    phone = StringField("Phone", validators=[Optional(), Length(max=20)])
    role = SelectField(
        "Role",
        choices=[("employee", "Employee"), ("admin", "Admin")],
        validators=[DataRequired()],
    )
    new_password = PasswordField(
        "New Password (leave blank to keep current)",
        validators=[Optional(), Length(min=6)],
    )
    submit = SubmitField("Update")


class TOTPForm(FlaskForm):
    token = StringField(
        "6-Digit Code", validators=[DataRequired(), Length(min=6, max=6)]
    )
    submit = SubmitField("Verify")


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def log_access(event_type: str, user_id: int = None, detail: str = None):
    """Record an access event and broadcast via WebSocket."""
    entry = AccessLog(
        user_id=user_id,
        event_type=event_type,
        detail=detail,
        ip_address=request.remote_addr,
    )
    db.session.add(entry)
    db.session.commit()
    # Broadcast to admin dashboards
    socketio.emit(
        "new_log",
        {
            "id": entry.id,
            "event_type": entry.event_type,
            "detail": entry.detail or "",
            "ip": entry.ip_address,
            "timestamp": entry.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": entry.user_id,
        },
        namespace="/dashboard",
    )


def admin_required(f):
    """Decorator: require the current user to be an admin."""
    from functools import wraps

    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)

    return decorated


# ---------------------------------------------------------------------------
# Routes — Public
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("employee_dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data) and user.is_active_user:
            # If 2FA is enabled, don't log in yet — send to verification
            if user.totp_enabled:
                session["pending_2fa_user_id"] = user.id
                session["pending_2fa_next"] = request.args.get("next")
                return redirect(url_for("verify_2fa"))

            # No 2FA — log in directly
            login_user(user, remember=False)
            log_access("login", user.id, f"Successful login as {user.role}")
            flash(f"Welcome back, {user.name}.", "success")
            next_page = request.args.get("next")
            if next_page and next_page.startswith("/admin") and not user.is_admin:
                next_page = None
            if user.is_admin:
                return redirect(next_page or url_for("admin_dashboard"))
            return redirect(next_page or url_for("employee_dashboard"))
        else:
            log_access(
                "access_denied",
                detail=f"Failed login for username: {form.username.data}",
            )
            flash("Invalid username or password.", "error")

    return render_template("login.html", form=form)


@app.route("/verify-2fa", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))

    user = db.session.get(User, user_id)
    if not user:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("login"))

    form = TOTPForm()
    if form.validate_on_submit():
        if user.verify_totp(form.token.data):
            session.pop("pending_2fa_user_id", None)
            next_page = session.pop("pending_2fa_next", None)
            login_user(user, remember=False)
            log_access("login", user.id, f"Successful login with 2FA as {user.role}")
            flash(f"Welcome back, {user.name}.", "success")
            if next_page and next_page.startswith("/admin") and not user.is_admin:
                next_page = None
            if user.is_admin:
                return redirect(next_page or url_for("admin_dashboard"))
            return redirect(next_page or url_for("employee_dashboard"))
        else:
            log_access("access_denied", user.id, "Invalid 2FA code")
            flash("Invalid code. Please try again.", "error")

    return render_template("verify_2fa.html", form=form, username=user.username)


@app.route("/logout")
@login_required
def logout():
    log_access("logout", current_user.id, f"{current_user.username} logged out")
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Routes — Admin
# ---------------------------------------------------------------------------


@app.route("/admin")
@login_required
@admin_required
def admin_dashboard():
    user_count = User.query.count()
    recent_logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).limit(10).all()
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    events_24h = AccessLog.query.filter(AccessLog.timestamp >= since).count()
    return render_template(
        "admin/dashboard.html",
        user_count=user_count,
        recent_logs=recent_logs,
        events_24h=events_24h,
    )


@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/export")
@login_required
@admin_required
def admin_users_export():
    users = User.query.order_by(User.created_at.desc()).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        [
            "username",
            "name",
            "email",
            "phone",
            "role",
            "active",
            "totp_enabled",
            "created_at",
        ]
    )
    for user in users:
        writer.writerow(
            [
                user.username,
                user.name,
                user.email,
                user.phone or "",
                user.role,
                user.is_active_user,
                user.totp_enabled,
                user.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            ]
        )

    log_access("data_exported", current_user.id, "Exported users list as CSV")
    filename = f"users_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/admin/users/new", methods=["GET", "POST"])
@login_required
@admin_required
def admin_register_user():
    form = RegisterUserForm()
    if form.validate_on_submit():
        # Check uniqueness
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists.", "error")
            return render_template("admin/register_user.html", form=form)
        if User.query.filter_by(email=form.email.data).first():
            flash("Email already registered.", "error")
            return render_template("admin/register_user.html", form=form)

        user = User(
            username=form.username.data,
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            role=form.role.data,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        log_access(
            "user_registered",
            current_user.id,
            f"Registered new {user.role}: {user.username}",
        )
        flash(f"User '{user.username}' registered successfully.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin/register_user.html", form=form)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@admin_required
def admin_edit_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    form = UpdateUserForm(obj=user)
    if form.validate_on_submit():
        # Check email uniqueness (excluding current user)
        existing = User.query.filter(
            User.email == form.email.data, User.id != user.id
        ).first()
        if existing:
            flash("Email already in use by another account.", "error")
            return render_template("admin/edit_user.html", form=form, user=user)

        user.name = form.name.data
        user.email = form.email.data
        user.phone = form.phone.data
        user.role = form.role.data
        if form.new_password.data:
            user.set_password(form.new_password.data)
        db.session.commit()
        log_access("user_updated", current_user.id, f"Updated user: {user.username}")
        flash(f"User '{user.username}' updated.", "success")
        return redirect(url_for("admin_users"))

    return render_template("admin/edit_user.html", form=form, user=user)


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@admin_required
def admin_toggle_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin_users"))

    user.is_active_user = not user.is_active_user
    db.session.commit()
    status = "activated" if user.is_active_user else "deactivated"
    log_access("user_toggled", current_user.id, f"{status} user: {user.username}")
    flash(f"User '{user.username}' has been {status}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/logs")
@login_required
@admin_required
def admin_logs():
    page = request.args.get("page", 1, type=int)
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).paginate(
        page=page, per_page=25, error_out=False
    )
    return render_template("admin/logs.html", logs=logs)


@app.route("/admin/logs/export")
@login_required
@admin_required
def admin_logs_export():
    logs = AccessLog.query.order_by(AccessLog.timestamp.desc()).all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "event_type", "username", "detail", "ip_address"])
    for log in logs:
        writer.writerow(
            [
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                log.event_type,
                log.user.username if log.user else "",
                log.detail or "",
                log.ip_address or "",
            ]
        )

    log_access("data_exported", current_user.id, "Exported access logs as CSV")
    filename = f"access_logs_{datetime.now(timezone.utc):%Y%m%d_%H%M%S}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ---------------------------------------------------------------------------
# Routes — Employee
# ---------------------------------------------------------------------------


@app.route("/employee")
@login_required
def employee_dashboard():
    my_logs = (
        AccessLog.query.filter_by(user_id=current_user.id)
        .order_by(AccessLog.timestamp.desc())
        .limit(10)
        .all()
    )
    return render_template("employee/dashboard.html", my_logs=my_logs)


# ---------------------------------------------------------------------------
# Routes — 2FA Setup (available to all authenticated users)
# ---------------------------------------------------------------------------


@app.route("/settings/2fa")
@login_required
def settings_2fa():
    """Show 2FA status and setup/disable options."""
    return render_template("settings/2fa.html")


@app.route("/settings/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    """Generate TOTP secret, show QR code, verify first token to enable."""
    if current_user.totp_enabled:
        flash("2FA is already enabled.", "info")
        return redirect(url_for("settings_2fa"))

    # Generate secret if not already pending
    if not current_user.totp_secret or request.method == "GET":
        current_user.generate_totp_secret()
        db.session.commit()

    form = TOTPForm()
    if form.validate_on_submit():
        if current_user.verify_totp(form.token.data):
            current_user.totp_enabled = True
            db.session.commit()
            log_access(
                "2fa_enabled", current_user.id, f"{current_user.username} enabled 2FA"
            )
            flash("Two-factor authentication enabled successfully.", "success")
            return redirect(url_for("settings_2fa"))
        else:
            flash("Invalid code. Please try again.", "error")

    # Generate QR code as base64 image
    uri = current_user.get_totp_uri()
    img = qrcode.make(uri, box_size=6, border=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

    return render_template(
        "settings/setup_2fa.html",
        form=form,
        qr_b64=qr_b64,
        secret=current_user.totp_secret,
    )


@app.route("/settings/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    """Disable 2FA for the current user."""
    current_user.totp_enabled = False
    current_user.totp_secret = None
    db.session.commit()
    log_access("2fa_disabled", current_user.id, f"{current_user.username} disabled 2FA")
    flash("Two-factor authentication has been disabled.", "info")
    return redirect(url_for("settings_2fa"))


@app.route("/admin/users/<int:user_id>/reset-2fa", methods=["POST"])
@login_required
@admin_required
def admin_reset_2fa(user_id):
    """Admin: reset 2FA for a user who lost their device."""
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    user.totp_enabled = False
    user.totp_secret = None
    db.session.commit()
    log_access("2fa_reset", current_user.id, f"Admin reset 2FA for: {user.username}")
    flash(f"2FA has been reset for '{user.username}'.", "success")
    return redirect(url_for("admin_users"))


# ---------------------------------------------------------------------------
# Routes — Location
# ---------------------------------------------------------------------------


@app.route("/admin/locations")
@login_required
@admin_required
def admin_locations():
    """Admin: view all users' latest locations on a map."""
    # Subquery: latest location per user
    from sqlalchemy import func

    latest_sub = (
        db.session.query(Location.user_id, func.max(Location.id).label("max_id"))
        .group_by(Location.user_id)
        .subquery()
    )

    latest_locations = (
        db.session.query(Location, User)
        .join(latest_sub, Location.id == latest_sub.c.max_id)
        .join(User, User.id == Location.user_id)
        .all()
    )

    markers = [
        {
            "user_id": loc.user_id,
            "name": user.name,
            "username": user.username,
            "lat": loc.latitude,
            "lon": loc.longitude,
            "accuracy": loc.accuracy,
            "timestamp": loc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }
        for loc, user in latest_locations
    ]

    return render_template("admin/locations.html", markers=markers)


@app.route("/employee/location")
@login_required
def employee_location():
    """Employee: view own location on a map + send location."""
    latest = (
        Location.query.filter_by(user_id=current_user.id)
        .order_by(Location.timestamp.desc())
        .first()
    )

    marker = None
    if latest:
        marker = {
            "lat": latest.latitude,
            "lon": latest.longitude,
            "accuracy": latest.accuracy,
            "timestamp": latest.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        }

    return render_template("employee/location.html", marker=marker)


# ---------------------------------------------------------------------------
# API — Location
# ---------------------------------------------------------------------------


@app.route("/api/location", methods=["POST"])
@csrf.exempt
@login_required
def update_location():
    data = request.get_json()
    if not data or "latitude" not in data or "longitude" not in data:
        return jsonify({"error": "Missing lat/lon"}), 400

    loc = Location(
        user_id=current_user.id,
        latitude=data["latitude"],
        longitude=data["longitude"],
        accuracy=data.get("accuracy"),
    )
    db.session.add(loc)
    db.session.commit()

    socketio.emit(
        "location_update",
        {
            "user_id": current_user.id,
            "username": current_user.username,
            "name": current_user.name,
            "lat": loc.latitude,
            "lon": loc.longitude,
            "accuracy": loc.accuracy,
            "timestamp": loc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        },
        namespace="/dashboard",
    )

    return jsonify({"status": "ok"}), 200


@app.route("/api/locations/latest")
@login_required
@admin_required
def api_latest_locations():
    """API: get all users' latest locations as JSON (for real-time map refresh)."""
    from sqlalchemy import func

    latest_sub = (
        db.session.query(Location.user_id, func.max(Location.id).label("max_id"))
        .group_by(Location.user_id)
        .subquery()
    )

    latest_locations = (
        db.session.query(Location, User)
        .join(latest_sub, Location.id == latest_sub.c.max_id)
        .join(User, User.id == Location.user_id)
        .all()
    )

    return jsonify(
        [
            {
                "user_id": loc.user_id,
                "name": user.name,
                "username": user.username,
                "lat": loc.latitude,
                "lon": loc.longitude,
                "accuracy": loc.accuracy,
                "timestamp": loc.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for loc, user in latest_locations
        ]
    )


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------


@app.errorhandler(403)
def forbidden(e):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template("errors/500.html"), 500


# ---------------------------------------------------------------------------
# Database init & seed
# ---------------------------------------------------------------------------


def seed_admin():
    """Create a default admin user if none exists."""
    if not User.query.filter_by(role="admin").first():
        admin = User(
            username=os.getenv("ADMIN_USERNAME", "admin"),
            name="System Administrator",
            email=os.getenv("ADMIN_EMAIL", "admin@ecube.local"),
            role="admin",
        )
        admin.set_password(os.getenv("ADMIN_PASSWORD", "admin123"))
        db.session.add(admin)
        db.session.commit()
        print(f"[SEED] Admin user created: {admin.username}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

# Runs on import so it also happens under gunicorn (which imports `app:app`
# directly and never executes the __main__ block below).
with app.app_context():
    db.create_all()
    seed_admin()

if __name__ == "__main__":
    print("\n  E-Cubed running at http://127.0.0.1:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=DEBUG)

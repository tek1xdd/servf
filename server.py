"""Flask сервер панели.

Изменения (декабрь 2025):
  - 3 роли пользователей: user / admin / super-admin
  - super-admin создаётся командой `flask --app server create-admin`
  - admin не может выдавать админку/супер-админку и не видит «внутрянку» диапазонов
    чужих пользователей (страницу /range/<id>).
  - добавлен аудит-лог действий (доступен только super-admin).
"""

# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps
import random
import re
from typing import Optional

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, inspect, or_, text
from werkzeug.security import check_password_hash, generate_password_hash


_GAME_POSITIONS = {}

def _get_game_bucket(range_id: int, game_index: int) -> dict:
    key = (int(range_id), int(game_index))
    bucket = _GAME_POSITIONS.get(key)
    if bucket is None:
        rnd = random.Random(int(range_id) * 1000 + int(game_index))
        pool_s = [1, 2, 3, 4, 5]
        pool_t = [1, 2, 3, 4, 5]
        rnd.shuffle(pool_s)
        rnd.shuffle(pool_t)
        bucket = {
            "svet": {},         # number -> pos
            "tma": {},          # number -> pos
            "svet_pool": pool_s,
            "tma_pool": pool_t,
            "created_at": datetime.utcnow(),
        }
        _GAME_POSITIONS[key] = bucket
    return bucket

def _assign_position(bucket: dict, number_int: int, side: str) -> int:
    """Выдаёт стабильную позицию 1..5 для number_int на данной стороне в текущем bucket."""
    side = "svet" if side == "svet" else "tma"
    other = "tma" if side == "svet" else "svet"

    # уже назначено на этой стороне
    if number_int in bucket[side]:
        return int(bucket[side][number_int])

    # если бот внезапно переопределил сторону в рамках одной игры
    if number_int in bucket[other]:
        old_pos = int(bucket[other][number_int])
        try:
            del bucket[other][number_int]
        except Exception:
            pass
        used = set(bucket[side].values())
        if old_pos not in used:
            bucket[side][number_int] = old_pos
            return old_pos

    pool_key = f"{side}_pool"
    pool = bucket.get(pool_key) or []
    if pool:
        pos = int(pool.pop())  # из перемешанного пула
    else:
        pos = random.randint(1, 5)
    bucket[side][number_int] = pos
    return pos

def _cleanup_old_game_buckets(range_id: int, keep_last: int = 6) -> None:
    """Оставляем последние keep_last bucket-ов на range_id, чтобы память не росла."""
    try:
        keys = [k for k in _GAME_POSITIONS.keys() if k[0] == int(range_id)]
        keys.sort(key=lambda x: x[1])
        for k in keys[:-keep_last]:
            _GAME_POSITIONS.pop(k, None)
    except Exception:
        pass


app = Flask(__name__)
app.config["SECRET_KEY"] = "super-secret-change-me"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///botpanel.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# ====== МОДЕЛИ ======
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    # legacy флаг админа (оставлен для совместимости)
    is_admin = db.Column(db.Boolean, default=False)
    # новый флаг супер-админа (имеет все права + просмотр «внутрянки» чужих диапазонов)
    is_super_admin = db.Column(db.Boolean, default=False)

    ranges = db.relationship("NumberRange", backref="user", lazy=True)

    @property
    def role(self) -> str:
        if self.is_super_admin:
            return "super-admin"
        if self.is_admin:
            return "admin"
        return "user"

    @property
    def is_staff(self) -> bool:
        return bool(self.is_admin or self.is_super_admin)


class NumberRange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    start = db.Column(db.Integer, nullable=False)
    end = db.Column(db.Integer, nullable=False)

    # какая пятёрка (левая/правая) играет на победу в текущей игре
    win_group = db.Column(db.String(8), default="right")  # "left" / "right"
    # сколько игр уже полностью сыграно (для рандомизации позиций)
    games_completed = db.Column(db.Integer, default=0)

    # последний сохранённый текст для автовходов (то, что ты вставляешь в textarea)
    autologin_text = db.Column(db.Text)  # <-- ДОБАВЛЕНО

    jobs = db.relationship(
        "AutoLoginJob",
        backref="range",
        lazy=True,
        cascade="all, delete-orphan",
    )
    logs = db.relationship(
        "AutoLoginLog",
        backref="range",
        lazy=True,
        cascade="all, delete-orphan",
    )
    commands = db.relationship(
        "RangeCommand",
        backref="range",
        lazy=True,
        cascade="all, delete-orphan",
    )
    account_states = db.relationship(
        "AccountState",
        backref="range",
        lazy=True,
        cascade="all, delete-orphan",
    )
    client_updates = db.relationship(
        "ClientUpdate",
        backref="range",
        lazy=True,
        cascade="all, delete-orphan",
    )


class AutoLoginJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    range_id = db.Column(db.Integer, db.ForeignKey("number_range.id"), nullable=False)
    number = db.Column(db.Integer, nullable=False)

    login = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    mail = db.Column(db.String(255))
    mail_password = db.Column(db.String(255))

    status = db.Column(db.String(32), default="pending")  # pending / taken / done / error
    error_message = db.Column(db.String(500))


class AutoLoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    range_id = db.Column(db.Integer, db.ForeignKey("number_range.id"), nullable=False)
    number = db.Column(db.Integer, nullable=False)
    message = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class RangeCommand(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    range_id = db.Column(db.Integer, db.ForeignKey("number_range.id"), nullable=False)
    number = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(50), nullable=False)  # novokek / played / autoconfig / startbot / stopbot
    status = db.Column(db.String(32), default="pending")  # pending / taken / done / error
    error_message = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AccountState(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    range_id = db.Column(db.Integer, db.ForeignKey("number_range.id"), nullable=False)
    number = db.Column(db.Integer, nullable=False)
    steam_id = db.Column(db.String(64), nullable=False)
    last_update = db.Column(db.DateTime, default=datetime.utcnow)
    # Lobby ID для этого номера (может быть NULL)
    lobby_id = db.Column(db.String(64))

    # сколько игр отыграл этот номер
    games_played = db.Column(db.Integer, default=0)
    # последняя сторона, за которую играл бот: "svet" / "tma"
    side = db.Column(db.String(8))
    # последняя позиция 1..5
    last_position = db.Column(db.Integer)
    # последний режим: True = WIN, False = LOOSE
    last_play_for_win = db.Column(db.Boolean)



class LobbyState(db.Model):
    """
    Текущее состояние lobby_id по номеру (одна строка на номер).
    Это сделано отдельно от AccountState, чтобы:
      - не зависеть от last_update (его трогают разные эндпоинты),
      - не "ломать" окно ожидания 6 сек при повторных отправках одного и того же lobby_id,
      - не ловить баг с несколькими AccountState-строками на один номер.
    """
    __table_args__ = (
        db.UniqueConstraint("range_id", "number", name="uq_lobby_state_range_number"),
    )

    id = db.Column(db.Integer, primary_key=True)
    range_id = db.Column(db.Integer, db.ForeignKey("number_range.id"), nullable=False)
    number = db.Column(db.Integer, nullable=False)

    lobby_id = db.Column(db.String(64))
    # Время, когда ЭТОТ номер впервые увидел текущий lobby_id
    lobby_seen_at = db.Column(db.DateTime)
    # Heartbeat: когда в последний раз этот номер прислал lobby_id
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)


class ClientUpdate(db.Model):
    """
    Событие «обновить клиент Dota» для конкретной пятёрки диапазона.
    Лидер (1 или 6) создаёт запись, остальные боты своей пятёрки читают.
    """
    id = db.Column(db.Integer, primary_key=True)
    range_id = db.Column(db.Integer, db.ForeignKey("number_range.id"), nullable=False)
    group_index = db.Column(db.Integer, nullable=False)  # 0, 1, 2... (каждая пятёрка)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ClientUpdateAck(db.Model):
    """
    Подтверждение (ack) от конкретного номера, что он выполнил обновление клиента
    по конкретному событию ClientUpdate.

    Нужно, чтобы после перезапуска бот НЕ выполнял одно и то же обновление снова.
    """
    __tablename__ = "client_update_ack_v2"
    __table_args__ = (
        db.UniqueConstraint("update_id", "number", name="uq_client_update_ack_v2"),
    )

    id = db.Column(db.Integer, primary_key=True)
    update_id = db.Column(db.Integer, db.ForeignKey("client_update.id"), nullable=False)
    number = db.Column(db.Integer, nullable=False)
    ack_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    """Аудит-лог действий пользователей.

    Логируем только действия из UI (изменения), чтобы super-admin мог отслеживать
    кто что делал.
    """

    id = db.Column(db.Integer, primary_key=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    actor_username = db.Column(db.String(50))
    actor_role = db.Column(db.String(20))

    action = db.Column(db.String(80), nullable=False)
    target_type = db.Column(db.String(50))
    target_id = db.Column(db.Integer)
    details = db.Column(db.Text)

    ip = db.Column(db.String(64))
    user_agent = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


_SCHEMA_READY = False


def ensure_schema() -> None:
    """Мягкая миграция схемы без Alembic.

    - создаёт таблицы, если их нет
    - добавляет новый столбец is_super_admin в старые базы
    """
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return

    db.create_all()

    try:
        insp = inspect(db.engine)
        if "user" in insp.get_table_names():
            cols = {c.get("name") for c in insp.get_columns("user")}
            if "is_super_admin" not in cols:
                # SQLite: ALTER TABLE ADD COLUMN
                with db.engine.begin() as conn:
                    conn.execute(text("ALTER TABLE user ADD COLUMN is_super_admin BOOLEAN DEFAULT 0"))
                    conn.execute(text("UPDATE user SET is_super_admin = 0 WHERE is_super_admin IS NULL"))
    except Exception:
        # если что-то пошло не так (нестандартная БД) — не валим весь сервер
        pass

    _SCHEMA_READY = True


# пробуем подготовить схему сразу при импорте приложения,
# чтобы `flask run` и CLI-команды работали без ручных миграций.
with app.app_context():
    ensure_schema()


# ====== ХЕЛПЕРЫ ======
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = User.query.get(session["user_id"])
        if not user or not user.is_staff:
            flash("Недостаточно прав.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper


def super_admin_required(f):
    """Доступ только для super-admin."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = User.query.get(session["user_id"])
        if not user or not user.is_super_admin:
            flash("Недостаточно прав (нужен super-admin).", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)

    return wrapper


def current_user():
    if "user_id" not in session:
        return None
    return User.query.get(session["user_id"])


def _get_request_ip() -> Optional[str]:
    try:
        fwd = request.headers.get("X-Forwarded-For")
        if fwd:
            return fwd.split(",")[0].strip()
        return request.remote_addr
    except Exception:
        return None


def audit(
    action: str,
    *,
    actor: Optional[User] = None,
    target_type: Optional[str] = None,
    target_id: Optional[int] = None,
    details: Optional[str] = None,
) -> None:
    """Записывает действие в AuditLog.

    ВАЖНО: не пиши сюда пароли/логины автовходов и другие секреты.
    """
    try:
        actor = actor or current_user()
    except Exception:
        actor = actor
    if not actor:
        return

    row = AuditLog(
        actor_user_id=actor.id,
        actor_username=actor.username,
        actor_role=actor.role,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details,
        ip=_get_request_ip(),
        user_agent=(request.headers.get("User-Agent") or "")[:255],
        created_at=datetime.utcnow(),
    )
    db.session.add(row)


def can_manage_user(actor: Optional[User], target: User) -> bool:
    """Кто может редактировать кого."""
    if not actor or not actor.is_staff:
        return False
    if actor.is_super_admin:
        return True
    # обычный admin НЕ управляет чужими staff-аккаунтами, но
    # может редактировать самого себя (например, сменить пароль).
    if actor.id == target.id:
        return True
    # обычный admin может управлять только простыми пользователями
    return not bool(target.is_staff)


def can_manage_ranges_of_user(actor: Optional[User], target: User) -> bool:
    """Кто может выдавать/отбирать диапазоны у конкретного пользователя."""
    if not actor or not actor.is_staff:
        return False
    if actor.is_super_admin:
        return True
    # обычный admin не выдаёт диапазоны другим staff-аккаунт... но
    # может управлять диапазонами самого себя.
    if actor.id == target.id:
        return True
    # admin может выдавать диапазоны только простым пользователям
    return not bool(target.is_staff)


@app.context_processor
def inject_current_user():
    # теперь в шаблонах есть переменная current_user
    return {"current_user": current_user()}


# ====== РОУТЫ ОСНОВНЫЕ ======
@app.route("/")
def index():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    if user.is_staff:
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("user_dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Неверный логин или пароль.", "danger")
        else:
            session["user_id"] = user.id
            # аудит входа
            audit("login", actor=user)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
            flash("Успешный вход.", "success")
            return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    user = current_user()
    if user:
        audit("logout", actor=user)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    session.clear()
    flash("Вы вышли из аккаунта.", "info")
    return redirect(url_for("login"))


# ====== АДМИНКА ======
@app.route("/admin")
@admin_required
def admin_dashboard():
    q_raw = (request.args.get("q") or "").strip()
    role = (request.args.get("role") or "all").strip()

    q = User.query

    # Фильтр по роли
    if role == "user":
        q = q.filter(User.is_admin.is_(False), User.is_super_admin.is_(False))
    elif role == "admin":
        q = q.filter(User.is_admin.is_(True), User.is_super_admin.is_(False))
    elif role in ("super", "super-admin", "super_admin"):
        q = q.filter(User.is_super_admin.is_(True))

    # Поиск по логину/ID/номеру в диапазонах
    if q_raw:
        conditions = [User.username.ilike(f"%{q_raw}%")]

        # если похоже на ID пользователя
        if q_raw.isdigit():
            num = int(q_raw)
            conditions.append(User.id == num)
            # плюс поиск по номеру в диапазонах (очень полезно для админки)
            conditions.append(
                User.ranges.any(and_(NumberRange.start <= num, NumberRange.end >= num))
            )
        else:
            # если похоже на диапазон "61-70" / "61–70"
            m = re.match(r"^(\d+)\s*[-–]\s*(\d+)$", q_raw)
            if m:
                a = int(m.group(1))
                b = int(m.group(2))
                if a > b:
                    a, b = b, a
                # находим пользователей, у которых есть диапазон, пересекающий запрос
                conditions.append(
                    User.ranges.any(and_(NumberRange.start <= b, NumberRange.end >= a))
                )

        q = q.filter(or_(*conditions))

    users = q.order_by(User.id).all()
    total_users = User.query.count()
    return render_template(
        "admin_dashboard.html",
        users=users,
        total_users=total_users,
        q_raw=q_raw,
        role=role,
    )


@app.route("/admin/users.new", methods=["GET", "POST"])
@admin_required
def admin_create_user():
    actor = current_user()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        requested_role = (request.form.get("role") or "user").strip()

        # обычный admin может создавать только простых пользователей
        if not actor or not actor.is_super_admin:
            requested_role = "user"

        if requested_role not in ("user", "admin", "super_admin"):
            requested_role = "user"

        is_admin = requested_role in ("admin", "super_admin")
        is_super_admin = requested_role == "super_admin"

        if not username or not password:
            flash("Логин и пароль обязательны.", "danger")
        elif User.query.filter_by(username=username).first():
            flash("Пользователь с таким логином уже существует.", "danger")
        else:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                is_admin=is_admin,
                is_super_admin=is_super_admin,
            )
            db.session.add(user)
            db.session.flush()  # получить user.id до commit
            audit(
                "user_create",
                actor=actor,
                target_type="user",
                target_id=user.id,
                details=f"created username={username} role={user.role}",
            )
            db.session.commit()
            flash("Пользователь создан.", "success")
            return redirect(url_for("admin_dashboard"))

    return render_template("admin_user_edit.html", user=None)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_user(user_id):
    actor = current_user()
    user = User.query.get_or_404(user_id)

    if not can_manage_user(actor, user):
        flash("Недостаточно прав для редактирования этого пользователя.", "danger")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        requested_role = (request.form.get("role") or ("super_admin" if user.is_super_admin else "admin" if user.is_admin else "user")).strip()

        # только super-admin может менять роли
        if not actor or not actor.is_super_admin:
            requested_role = "user"

        if requested_role not in ("user", "admin", "super_admin"):
            requested_role = "user"

        is_admin = requested_role in ("admin", "super_admin")
        is_super_admin = requested_role == "super_admin"

        # защита: не даём удалить последнего super-admin
        if user.is_super_admin and not is_super_admin:
            cnt = User.query.filter_by(is_super_admin=True).count()
            if cnt <= 1:
                flash("Нельзя убрать роль последнего super-admin.", "danger")
                return redirect(url_for("admin_edit_user", user_id=user.id))

        if not username:
            flash("Логин обязателен.", "danger")
        else:
            old_username = user.username
            old_role = user.role

            user.username = username
            # роли меняем только если super-admin
            if actor and actor.is_super_admin:
                user.is_admin = bool(is_admin)
                user.is_super_admin = bool(is_super_admin)
            # пароль можно менять и обычному admin (для простых пользователей)
            password_changed = False
            if password:
                user.password_hash = generate_password_hash(password)
                password_changed = True

            audit_details = []
            if old_username != user.username:
                audit_details.append(f"username: {old_username} -> {user.username}")
            if old_role != user.role:
                audit_details.append(f"role: {old_role} -> {user.role}")
            if password_changed:
                audit_details.append("password: changed")

            audit(
                "user_update",
                actor=actor,
                target_type="user",
                target_id=user.id,
                details="; ".join(audit_details) if audit_details else "no visible changes",
            )
            db.session.commit()
            flash("Пользователь обновлён.", "success")
            return redirect(url_for("admin_dashboard"))

    return render_template("admin_user_edit.html", user=user)


@app.route("/admin/users/<int:user_id>/ranges", methods=["GET", "POST"])
@admin_required
def admin_user_ranges(user_id):
    actor = current_user()
    user = User.query.get_or_404(user_id)

    if not can_manage_ranges_of_user(actor, user):
        flash("Недостаточно прав для управления диапазонами этого пользователя.", "danger")
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        # Можно ввести как обычный диапазон 61-70,
        # так и большой (например 31-80) — он будет автоматически
        # разбит по 10 номеров: 31-40, 41-50, ...
        rng_text = (request.form.get("range", "") or "").strip()
        rng_text = rng_text.replace(" ", "")
        rng_text = rng_text.replace("–", "-")  # en-dash

        m = re.match(r"^(\d+)\s*-\s*(\d+)$", rng_text)
        if not m:
            flash("Неверный формат диапазона. Пример: 61-70 или 31-80", "danger")
        else:
            start = int(m.group(1))
            end = int(m.group(2))
            if start > end:
                start, end = end, start

            CHUNK = 10
            segments: list[tuple[int, int]] = []
            cur = start
            while cur <= end:
                seg_end = min(cur + CHUNK - 1, end)
                segments.append((cur, seg_end))
                cur = seg_end + 1

            created: list[tuple[int, int, int]] = []  # (start, end, range_id)
            skipped_existing: list[tuple[int, int]] = []
            skipped_conflicts: list[tuple[int, int, str]] = []  # (start, end, reason)

            for seg_start, seg_end in segments:
                # если уже есть ровно такой диапазон у этого пользователя
                exists = NumberRange.query.filter_by(
                    user_id=user.id,
                    start=seg_start,
                    end=seg_end,
                ).first()
                if exists:
                    skipped_existing.append((seg_start, seg_end))
                    continue

                # Проверяем пересечения по ВСЕЙ базе (важно, т.к. бот по номеру
                # ищет первый попавшийся диапазон, и пересечения ломают логику).
                overlaps = (
                    NumberRange.query
                    .filter(NumberRange.start <= seg_end, NumberRange.end >= seg_start)
                    .all()
                )
                # допускаем только «идеальный дубль» (мы его уже отфильтровали выше)
                if overlaps:
                    # покажем в сообщении владельца и конфликтующий диапазон
                    conflict = overlaps[0]
                    owner = User.query.get(conflict.user_id)
                    owner_name = owner.username if owner else f"user_id={conflict.user_id}"
                    skipped_conflicts.append(
                        (seg_start, seg_end, f"пересекается с {conflict.start}-{conflict.end} ({owner_name})")
                    )
                    continue

                rng = NumberRange(user=user, start=seg_start, end=seg_end)
                db.session.add(rng)
                db.session.flush()
                created.append((seg_start, seg_end, int(rng.id)))

            # аудит и коммит
            if created or skipped_existing or skipped_conflicts:
                # компактное описание
                def _fmt_pairs(pairs: list[tuple[int, int]]) -> str:
                    return ", ".join([f"{a}-{b}" for a, b in pairs])

                created_pairs = [(a, b) for a, b, _ in created]
                details_parts = [
                    f"input={start}-{end}",
                    f"created={len(created_pairs)}",
                ]
                if created_pairs:
                    details_parts.append(f"created_ranges={_fmt_pairs(created_pairs)}")
                if skipped_existing:
                    details_parts.append(f"skipped_existing={len(skipped_existing)}")
                if skipped_conflicts:
                    details_parts.append(f"skipped_conflicts={len(skipped_conflicts)}")

                audit(
                    "range_create",
                    actor=actor,
                    target_type="user",
                    target_id=user.id,
                    details="; ".join(details_parts),
                )

            db.session.commit()

            # флеш сообщения
            if created:
                flash(f"Добавлено диапазонов: {len(created)}.", "success")
            if skipped_existing:
                flash(
                    f"Пропущено (уже были): {len(skipped_existing)} ({_fmt_pairs(skipped_existing)}).",
                    "info",
                )
            if skipped_conflicts:
                # показываем до 5 конфликтов, чтобы не спамить
                preview = "; ".join([f"{a}-{b}: {reason}" for a, b, reason in skipped_conflicts[:5]])
                more = "" if len(skipped_conflicts) <= 5 else f" (+ещё {len(skipped_conflicts)-5})"
                flash(f"Не добавлено из-за пересечений: {len(skipped_conflicts)}. {preview}{more}", "danger")

    ranges = NumberRange.query.filter_by(user_id=user.id).order_by(
        NumberRange.start
    ).all()
    return render_template("admin_user_ranges.html", user=user, ranges=ranges)


@app.route("/admin/ranges/<int:range_id>/delete")
@admin_required
def admin_delete_range(range_id):
    actor = current_user()
    rng = NumberRange.query.get_or_404(range_id)

    owner = User.query.get(rng.user_id)
    if owner and not can_manage_ranges_of_user(actor, owner):
        flash("Недостаточно прав для удаления этого диапазона.", "danger")
        return redirect(url_for("admin_dashboard"))

    user_id = rng.user_id
    details = f"deleted range {rng.start}-{rng.end} (range_id={rng.id}) for user_id={user_id}"
    db.session.delete(rng)
    audit(
        "range_delete",
        actor=actor,
        target_type="range",
        target_id=range_id,
        details=details,
    )
    db.session.commit()
    flash("Диапазон удалён.", "info")
    return redirect(url_for("admin_user_ranges", user_id=user_id))


@app.route("/admin/audit")
@super_admin_required
def admin_audit_logs():
    """Просмотр аудит-логов (только super-admin)."""
    q_user = (request.args.get("user") or "").strip()
    q_action = (request.args.get("action") or "").strip()

    q = AuditLog.query.order_by(AuditLog.created_at.desc())
    if q_user:
        q = q.filter(AuditLog.actor_username.like(f"%{q_user}%"))
    if q_action:
        q = q.filter(AuditLog.action.like(f"%{q_action}%"))

    logs = q.limit(500).all()
    return render_template(
        "admin_audit_logs.html",
        logs=logs,
        q_user=q_user,
        q_action=q_action,
    )


# ====== КАБИНЕТ ПОЛЬЗОВАТЕЛЯ ======
@app.route("/cabinet")
@login_required
def user_dashboard():
    user = current_user()
    ranges = NumberRange.query.filter_by(user_id=user.id).order_by(
        NumberRange.start
    ).all()
    return render_template(
        "user_dashboard.html",
        user=user,
        ranges=ranges,
    )


@app.route("/range/<int:range_id>")
@login_required
def user_range(range_id: int):
    user = current_user()
    rng = NumberRange.query.get_or_404(range_id)

    # только super-admin видит «внутрянку» чужих диапазонов
    if not user.is_super_admin and rng.user_id != user.id:
        flash("У вас нет прав на этот диапазон.", "danger")
        return redirect(url_for("user_dashboard"))

    tab = request.args.get("tab", "settings")
    if tab not in ("settings", "autologin", "logs", "state"):
        tab = "settings"

    # ВСЕ задачи по диапазону (их теперь максимум = размер диапазона)
    jobs = AutoLoginJob.query.filter_by(range_id=rng.id).order_by(
        AutoLoginJob.id.desc()
    ).all()

    logs = AutoLoginLog.query.filter_by(range_id=rng.id).order_by(
        AutoLoginLog.created_at.desc()
    ).limit(200).all()

    states = AccountState.query.filter_by(range_id=rng.id).order_by(
        AccountState.number,
        AccountState.steam_id,
    ).all()

    return render_template(
        "user_range.html",
        user=user,
        rng=rng,
        tab=tab,
        jobs=jobs,
        logs=logs,
        states=states,
    )


@app.route("/range/<int:range_id>/logs-json")
@login_required
def range_logs_json(range_id: int):
    user = current_user()
    rng = NumberRange.query.get_or_404(range_id)

    if not user.is_super_admin and rng.user_id != user.id:
        return jsonify({"ok": False, "error": "forbidden"}), 403

    logs = AutoLoginLog.query.filter_by(range_id=rng.id).order_by(
        AutoLoginLog.created_at.desc()
    ).limit(200).all()

    data = [
        {
            "time": l.created_at.strftime("%H:%M:%S"),
            "number": l.number,
            "message": l.message,
        }
        for l in reversed(logs)
    ]
    return jsonify({"ok": True, "logs": data})


@app.route("/range/<int:range_id>/autologin/start", methods=["POST"])
@login_required
def user_range_autologin_start(range_id):
    """
    Старт автовходов:
      - старые задачи ПОЛНОСТЬЮ очищаем для диапазона;
      - создаём новые задачи только под текущий список аккаунтов;
      - сырой текст аккаунтов сохраняем в rng.autologin_text (чтобы остался в textarea).
    """
    user = current_user()
    rng = NumberRange.query.get_or_404(range_id)

    if not user.is_super_admin and rng.user_id != user.id:
        flash("У вас нет прав на этот диапазон.", "danger")
        return redirect(url_for("user_dashboard"))

    raw = request.form.get("accounts", "")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]

    if not lines:
        flash("Нужно указать хотя бы одну строку с логином.", "danger")
        return redirect(url_for("user_range", range_id=range_id, tab="autologin"))

    # сохраняем текст, чтобы он оставался в форме
    rng.autologin_text = raw

    # УДАЛЯЕМ ВСЕ старые задачи этого диапазона (а не только pending),
    # чтобы всегда было максимум «по одному на номер».
    AutoLoginJob.query.filter_by(range_id=rng.id).delete()

    numbers = list(range(rng.start, rng.end + 1))
    count = min(len(lines), len(numbers))
    created = 0

    for i in range(count):
        line = lines[i]
        parts = line.split(":")
        if len(parts) < 2:
            continue

        login = parts[0]
        password = parts[1]
        mail = parts[2] if len(parts) > 2 else None
        mail_password = parts[3] if len(parts) > 3 else None

        num = numbers[i]

        job = AutoLoginJob(
            range_id=rng.id,
            number=num,
            login=login,
            password=password,
            mail=mail,
            mail_password=mail_password,
            status="pending",
        )
        db.session.add(job)
        created += 1

    audit(
        "autologin_start",
        actor=user,
        target_type="range",
        target_id=rng.id,
        details=f"range={rng.start}-{rng.end}; jobs_created={created}",
    )

    db.session.commit()
    flash(f"Создано задач автологина: {created}.", "success")
    return redirect(url_for("user_range", range_id=range_id, tab="autologin"))


@app.route("/range/<int:range_id>/command", methods=["POST"])
@login_required
def user_range_command(range_id):
    user = current_user()
    rng = NumberRange.query.get_or_404(range_id)

    if not user.is_super_admin and rng.user_id != user.id:
        flash("У вас нет прав на этот диапазон.", "danger")
        return redirect(url_for("user_dashboard"))

    action = request.form.get("action")

    labels = {
        "startbot": "Запуск бота",
        "stopbot": "Остановить бота",
        "novokek": "Новичок (750 MMR)",
        "played": "Я уже играл (1600 MMR)",
        "autoconfig": "Автонастройка",
    }

    if action not in labels:
        flash("Неизвестное действие.", "danger")
        return redirect(url_for("user_range", range_id=range_id, tab="settings"))

    for num in range(rng.start, rng.end + 1):
        cmd = RangeCommand(
            range_id=rng.id,
            number=num,
            action=action,
            status="pending",
        )
        db.session.add(cmd)

    total = int(rng.end) - int(rng.start) + 1
    audit(
        "range_command",
        actor=user,
        target_type="range",
        target_id=rng.id,
        details=f"action={action}; total_numbers={total}",
    )

    db.session.commit()

    flash(f"Команда «{labels[action]}» отправлена на ботов диапазона.", "success")
    return redirect(url_for("user_range", range_id=range_id, tab="settings"))


@app.route("/range/<int:range_id>/game-settings", methods=["POST"])
@login_required
def user_range_game_settings(range_id):
    user = current_user()
    rng = NumberRange.query.get_or_404(range_id)

    if not user.is_super_admin and rng.user_id != user.id:
        flash("У вас нет прав на этот диапазон.", "danger")
        return redirect(url_for("user_dashboard"))

    action = request.form.get("action")

    if action == "set_win_group":
        win_group = request.form.get("win_group")
        if win_group not in ("left", "right"):
            flash("Неверное значение стороны.", "danger")
            return redirect(url_for("user_range", range_id=rng.id, tab="settings"))
        rng.win_group = win_group
        audit(
            "range_set_win_group",
            actor=user,
            target_type="range",
            target_id=rng.id,
            details=f"win_group={win_group}",
        )
        db.session.commit()
        flash("Режим победа/поражение обновлён.", "success")
        return redirect(url_for("user_range", range_id=rng.id, tab="settings"))

    elif action == "reset_games":
        rng.games_completed = 0
        rows = AccountState.query.filter_by(range_id=rng.id).all()
        for r in rows:
            r.games_played = 0
        audit(
            "range_reset_games",
            actor=user,
            target_type="range",
            target_id=rng.id,
            details=f"reset games_played for {len(rows)} rows",
        )
        db.session.commit()
        flash("Счётчики игр для диапазона сброшены.", "success")
        return redirect(url_for("user_range", range_id=rng.id, tab="state"))

    else:
        flash("Неизвестное действие.", "danger")
        return redirect(url_for("user_range", range_id=rng.id, tab="settings"))


# ====== API ДЛЯ АВТОВХОДА ======
@app.route("/api/autologin/next", methods=["POST"])
def api_autologin_next():
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")

    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    job = (
        AutoLoginJob.query
        .filter_by(number=number, status="pending")
        .order_by(AutoLoginJob.id)
        .first()
    )

    if not job:
        return jsonify({"ok": True, "job": None})

    job.status = "taken"
    db.session.commit()

    return jsonify({
        "ok": True,
        "job": {
            "id": job.id,
            "number": job.number,
            "login": job.login,
            "password": job.password,
            "mail": job.mail,
            "mail_password": job.mail_password,
        }
    })


@app.route("/api/autologin/result", methods=["POST"])
def api_autologin_result():
    data = request.get_json(force=True, silent=True) or {}
    job_id = data.get("id")
    status = data.get("status")
    message = data.get("message", "")

    if not job_id or status not in ("done", "error"):
        return jsonify({"ok": False, "error": "bad payload"}), 400

    job = AutoLoginJob.query.get(job_id)
    if not job:
        return jsonify({"ok": False, "error": "job not found"}), 404

    job.status = status
    job.error_message = message[:500]
    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/autologin/log", methods=["POST"])
def api_autologin_log():
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")
    message = (data.get("message") or "").strip()

    if number is None or not message:
        return jsonify({"ok": False, "error": "number and message required"}), 400

    rng = (
        NumberRange.query
        .filter(NumberRange.start <= int(number), NumberRange.end >= int(number))
        .first()
    )
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    log_row = AutoLoginLog(
        range_id=rng.id,
        number=int(number),
        message=message[:500],
    )
    db.session.add(log_row)
    db.session.commit()

    return jsonify({"ok": True})


# ====== API ДЛЯ КОМАНД ======
@app.route("/api/command/next", methods=["POST"])
def api_command_next():
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")

    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    cmd = (
        RangeCommand.query
        .filter_by(number=number, status="pending")
        .order_by(RangeCommand.id)
        .first()
    )
    if not cmd:
        return jsonify({"ok": True, "command": None})

    cmd.status = "taken"
    db.session.commit()

    return jsonify({
        "ok": True,
        "command": {
            "id": cmd.id,
            "action": cmd.action,
        }
    })


@app.route("/api/command/result", methods=["POST"])
def api_command_result():
    data = request.get_json(force=True, silent=True) or {}
    cmd_id = data.get("id")
    status = data.get("status")
    message = data.get("message", "")

    if not cmd_id or status not in ("done", "error"):
        return jsonify({"ok": False, "error": "bad payload"}), 400

    cmd = RangeCommand.query.get(cmd_id)
    if not cmd:
        return jsonify({"ok": False, "error": "command not found"}), 404

    cmd.status = status
    cmd.error_message = message[:500]
    db.session.commit()
    return jsonify({"ok": True})




@app.route("/api/command/state")
def api_command_state():
    """
    GET /api/command/state?number=51

    Возвращает "липкое" состояние startbot/stopbot для указанного number.

    Зачем:
      - Команда startbot/stopbot в текущей схеме — одноразовая и быстро уходит в done.
      - Если клиент (exe) перезапустили, он может "не увидеть" startbot и будет спать.
      - По этому эндпоинту клиент может синхронизироваться и понять, нужно ли ему работать.
    """
    number = request.args.get("number", type=int)
    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    cmd = (
        RangeCommand.query
        .filter(
            RangeCommand.number == int(number),
            RangeCommand.action.in_(("startbot", "stopbot")),
        )
        .order_by(RangeCommand.id.desc())
        .first()
    )

    if not cmd:
        return jsonify({
            "ok": True,
            "active": False,
            "last_action": None,
            "id": None,
            "created_at": None,
        })

    return jsonify({
        "ok": True,
        "active": True if cmd.action == "startbot" else False,
        "last_action": cmd.action,
        "id": cmd.id,
        "created_at": cmd.created_at.isoformat() + "Z" if cmd.created_at else None,
    })

# ====== API ДЛЯ СОСТОЯНИЯ АККАУНТОВ (STEAM ID) ======
@app.route("/api/accounts/update", methods=["POST"])
def api_accounts_update():
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")
    steam_ids = data.get("steam_ids") or []

    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    try:
        number_int = int(number)
    except Exception:
        return jsonify({"ok": False, "error": "bad number"}), 400

    if not steam_ids:
        return jsonify({"ok": False, "error": "no steam_ids"}), 400

    rng = (
        NumberRange.query
        .filter(NumberRange.start <= number_int, NumberRange.end >= number_int)
        .first()
    )
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    # сохраняем старые счётчики игр по steam_id
    old_rows = AccountState.query.filter_by(range_id=rng.id, number=number_int).all()
    old_games = {r.steam_id: (r.games_played or 0) for r in old_rows}

    # чтобы lobby_id не пропадал при перезапуске EXE и повторной отправке /api/accounts/update
    old_lobby_id = None
    for r in sorted(old_rows, key=lambda x: x.last_update or datetime.min, reverse=True):
        if r.lobby_id:
            old_lobby_id = r.lobby_id
            break

    for r in old_rows:
        db.session.delete(r)

    for sid in steam_ids:
        sid_str = str(sid).strip()
        if not sid_str:
            continue
        row = AccountState(
            range_id=rng.id,
            number=number_int,
            steam_id=sid_str,
            last_update=datetime.utcnow(),
            lobby_id=old_lobby_id,
            games_played=old_games.get(sid_str, 0),
        )
        db.session.add(row)

    db.session.commit()
    return jsonify({"ok": True})


@app.route("/api/accounts/party")
def api_accounts_party():
    number = request.args.get("number", type=int)
    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    rng = (
        NumberRange.query
        .filter(NumberRange.start <= number, NumberRange.end >= number)
        .first()
    )
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    last_digit = abs(number) % 10
    if last_digit not in (1, 6):
        return jsonify({"ok": True, "party": []})

    party_numbers = []
    for i in range(1, 5):
        n = number + i
        if n <= rng.end:
            party_numbers.append(n)

    if not party_numbers:
        return jsonify({"ok": True, "party": []})

    rows = (
        AccountState.query
        .filter(
            AccountState.range_id == rng.id,
            AccountState.number.in_(party_numbers),
        )
        .order_by(AccountState.number, AccountState.last_update.desc())
        .all()
    )

    id_map = {}
    for row in rows:
        if row.number not in id_map:
            id_map[row.number] = row.steam_id

    party = [{"number": n, "steam_id": id_map[n]} for n in party_numbers if n in id_map]
    return jsonify({"ok": True, "party": party})


# ====== API ДЛЯ LOBBY ID ======
@app.route("/api/accounts/lobby_update", methods=["POST"])
def api_accounts_lobby_update():
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")
    lobby_id = (data.get("lobby_id") or "").strip()

    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400
    if not lobby_id:
        return jsonify({"ok": False, "error": "no lobby_id"}), 400

    try:
        number_int = int(number)
    except Exception:
        return jsonify({"ok": False, "error": "bad number"}), 400

    rng = (
        NumberRange.query
        .filter(NumberRange.start <= number_int, NumberRange.end >= number_int)
        .first()
    )
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    now = datetime.utcnow()

    # 1) Надёжное хранение lobby_id (одна строка на номер)
    st = LobbyState.query.filter_by(range_id=rng.id, number=number_int).first()
    if not st:
        st = LobbyState(
            range_id=rng.id,
            number=number_int,
            lobby_id=lobby_id,
            lobby_seen_at=now,
            updated_at=now,
        )
        db.session.add(st)
    else:
        if st.lobby_id != lobby_id:
            st.lobby_id = lobby_id
            st.lobby_seen_at = now
        st.updated_at = now

    # 2) Для отображения в таблице «Состояние аккаунтов» — проставляем lobby_id во ВСЕ строки номера
    rows = AccountState.query.filter_by(range_id=rng.id, number=number_int).all()
    if not rows:
        row = AccountState(
            range_id=rng.id,
            number=number_int,
            steam_id="unknown",
            last_update=now,
        )
        db.session.add(row)
        rows = [row]

    for r in rows:
        r.lobby_id = lobby_id
        # last_update можно использовать как heartbeat (чтобы видно было что бот жив)
        r.last_update = now

    db.session.commit()
    return jsonify({"ok": True})
@app.route("/api/accounts/lobby_state")
def api_accounts_lobby_state():
    """
    GET /api/accounts/lobby_state?number=51

    Ответ:
      { "ok": true, "mode": "same"|"different"|"waiting", "lobby_id": "..."|null }

    Логика:
      - как только появляется новый lobby_id в диапазоне, даём ~6 секунд,
        чтобы остальные успели его отправить → в это время всегда "waiting"
      - после окна:
          * если есть хотя бы один ДРУГОЙ lobby_id → "different"
          * если нет других, но не у всех номеров есть lobby_id → "different"
          * если у всех номеров lobby_id == мой → "same"

    ВАЖНО:
      Тут мы читаем lobby_id из LobbyState (отдельная таблица), чтобы:
        - не зависеть от AccountState.last_update (его трогают разные эндпоинты),
        - не ловить рандом из-за нескольких строк AccountState на один номер.
    """
    number = request.args.get("number", type=int)
    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    rng = (
        NumberRange.query
        .filter(NumberRange.start <= number, NumberRange.end >= number)
        .first()
    )
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    now = datetime.utcnow()
    WAIT_SECONDS = 6

    # Через какое время считать данные "протухшими" (бот упал/не шлёт lobby_id)
    # Нужно, чтобы старый lobby_id с упавшей виртуалки не ломал всем mode.
    TTL_SECONDS = 15 * 60  # 15 минут
    cutoff = now - timedelta(seconds=TTL_SECONDS)

    my_state = LobbyState.query.filter_by(range_id=rng.id, number=number).first()
    if (
        (not my_state)
        or (not my_state.lobby_id)
        or (not my_state.updated_at)
        or (my_state.updated_at < cutoff)
    ):
        return jsonify({"ok": True, "mode": "waiting", "lobby_id": None})

    my_lobby = my_state.lobby_id

    # --- 1) Когда в диапазоне впервые появился ЭТОТ lobby_id? ---
    rows_same = (
        LobbyState.query
        .filter(
            LobbyState.range_id == rng.id,
            LobbyState.lobby_id == my_lobby,
            LobbyState.updated_at >= cutoff,
        )
        .all()
    )

    first_time = None
    for r in rows_same:
        if r.lobby_seen_at:
            if first_time is None or r.lobby_seen_at < first_time:
                first_time = r.lobby_seen_at

    # если lobby_id появился меньше WAIT_SECONDS назад — ещё ждём
    if first_time:
        age = (now - first_time).total_seconds()
        if age < WAIT_SECONDS:
            return jsonify({"ok": True, "mode": "waiting", "lobby_id": my_lobby})

    # --- 2) Окно прошло — сверяем по всему диапазону ---
    numbers = list(range(rng.start, rng.end + 1))

    rows = (
        LobbyState.query
        .filter(
            LobbyState.range_id == rng.id,
            LobbyState.number.in_(numbers),
            LobbyState.updated_at >= cutoff,
            LobbyState.lobby_id.isnot(None),
        )
        .all()
    )

    latest_per_number = {int(r.number): r.lobby_id for r in rows}

    # 1) Если есть хоть один lobby_id, отличающийся от моего → different
    if any(lobby != my_lobby for lobby in latest_per_number.values()):
        return jsonify({"ok": True, "mode": "different", "lobby_id": my_lobby})

    # 2) Если НЕТ конфликтов, но не все номера диапазона прислали lobby_id → тоже different
    if len(latest_per_number) < len(numbers):
        return jsonify({"ok": True, "mode": "different", "lobby_id": my_lobby})

    # 3) Иначе: каждый номер имеет lobby_id == my_lobby → same
    return jsonify({"ok": True, "mode": "same", "lobby_id": my_lobby})
@app.route("/api/accounts/lobby_reset", methods=["POST"])
def api_accounts_lobby_reset():
    """
    Клиент может вызывать этот метод после нажатия accept,
    но мы больше НЕ трогаем lobby_id в базе, чтобы не ломать
    вычисление same/different для остальных ботов.
    """
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")

    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    # никаких изменений в БД не делаем
    return jsonify({"ok": True})



# ====== API ДЛЯ ОБНОВЛЕНИЯ КЛИЕНТА (client_igri) ======

def _client_update_group_numbers(rng: NumberRange, group_index: int) -> list[int]:
    """Возвращает номера (в пределах диапазона) для конкретной пятёрки group_index."""
    start_num = int(rng.start) + int(group_index) * 5
    if start_num > int(rng.end):
        return []
    end_num = min(start_num + 4, int(rng.end))
    return list(range(start_num, end_num + 1))


def _client_update_is_done(update_row: ClientUpdate, group_numbers: list[int]) -> tuple[bool, set[int]]:
    """(done, acked_numbers_set) для события update_row."""
    acks = ClientUpdateAck.query.filter_by(update_id=update_row.id).all()
    acked_numbers = {int(a.number) for a in acks if a.number is not None}
    done = bool(group_numbers) and all(n in acked_numbers for n in group_numbers)
    return done, acked_numbers


@app.route("/api/client_update/leader", methods=["POST"])
def api_client_update_leader():
    """
    Лидер пятёрки сообщает, что увидел окно обновления клиента.
    Сервер создаёт событие для всей пятёрки (или возвращает уже существующее),
    чтобы боты обновились РОВНО ОДИН раз на событие.
    """
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")

    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    try:
        number_int = int(number)
    except Exception:
        return jsonify({"ok": False, "error": "bad number"}), 400

    rng = (
        NumberRange.query
        .filter(NumberRange.start <= number_int, NumberRange.end >= number_int)
        .first()
    )
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    total = int(rng.end) - int(rng.start) + 1
    if total <= 0:
        return jsonify({"ok": False, "error": "empty range"}), 400

    rel = number_int - int(rng.start)
    if rel < 0 or rel >= total:
        return jsonify({"ok": False, "error": "number not in range"}), 400

    group_index = rel // 5
    group_numbers = _client_update_group_numbers(rng, group_index)

    # --- Анти-спам / дедупликация ---
    # Если уже есть "активное" событие (не все отписались ack), возвращаем его, чтобы не плодить 100 событий.
    # Если событие зависло очень давно (STALE_SECONDS) — разрешаем создать новое.
    STALE_SECONDS = 6 * 3600  # 6 часов
    DONE_DEBOUNCE_SECONDS = 120  # 2 минуты (защита от двойного клика/фолс-позитива)

    now = datetime.utcnow()

    last_row = (
        ClientUpdate.query
        .filter_by(range_id=rng.id, group_index=group_index)
        .order_by(ClientUpdate.id.desc())
        .first()
    )
    if last_row:
        done, _acked = _client_update_is_done(last_row, group_numbers)
        age = None
        try:
            if last_row.created_at:
                age = (now - last_row.created_at).total_seconds()
        except Exception:
            age = None

        if not done:
            # Если ещё не все ack — считаем событие активным и возвращаем его (пока не устарело)
            if age is None or age < STALE_SECONDS:
                return jsonify({
                    "ok": True,
                    "id": last_row.id,
                    "group_index": group_index,
                    "reused": True,
                    "done": False,
                })

        # Если done, но лидер "дёрнул" ручку повторно сразу — тоже вернём прошлое, чтобы не пересоздавать
        if done and age is not None and age < DONE_DEBOUNCE_SECONDS:
            return jsonify({
                "ok": True,
                "id": last_row.id,
                "group_index": group_index,
                "reused": True,
                "done": True,
            })

    # Создаём новое событие
    row = ClientUpdate(
        range_id=rng.id,
        group_index=group_index,
        created_at=now,
    )
    db.session.add(row)
    db.session.commit()

    return jsonify({
        "ok": True,
        "id": row.id,
        "group_index": group_index,
        "reused": False,
        "done": False,
        "created_at": row.created_at.isoformat() + "Z",
    })


@app.route("/api/client_update/check")
def api_client_update_check():
    """
    GET /api/client_update/check?number=51

    Возвращает ПОСЛЕДНЕЕ событие обновления клиента для пятёрки,
    НО только если данный number ещё НЕ подтвердил (ack) это событие.

    Ответ:
      { "ok": true, "id": <int> | null, "group_index": <int> | null, "created_at": <str> | null }
    """
    number = request.args.get("number", type=int)
    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    rng = (
        NumberRange.query
        .filter(NumberRange.start <= number, NumberRange.end >= number)
        .first()
    )
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    total = int(rng.end) - int(rng.start) + 1
    if total <= 0:
        return jsonify({"ok": True, "id": None, "group_index": None})

    rel = int(number) - int(rng.start)
    if rel < 0 or rel >= total:
        return jsonify({"ok": False, "error": "number not in range"}), 400

    group_index = rel // 5
    group_numbers = _client_update_group_numbers(rng, group_index)

    row = (
        ClientUpdate.query
        .filter_by(range_id=rng.id, group_index=group_index)
        .order_by(ClientUpdate.id.desc())
        .first()
    )
    if not row:
        return jsonify({"ok": True, "id": None, "group_index": group_index})

    done, acked_numbers = _client_update_is_done(row, group_numbers)

    # если событие уже закрыто (все ack), или этот бот уже ack — ничего не возвращаем
    if done or int(number) in acked_numbers:
        return jsonify({
            "ok": True,
            "id": None,
            "group_index": group_index,
            "created_at": None,
            "done": bool(done),
            "acked": len(acked_numbers),
            "total": len(group_numbers),
        })

    return jsonify({
        "ok": True,
        "id": row.id,
        "group_index": row.group_index,
        "created_at": row.created_at.isoformat() + "Z",
        "done": bool(done),
        "acked": len(acked_numbers),
        "total": len(group_numbers),
    })


@app.route("/api/client_update/ack", methods=["POST"])
def api_client_update_ack():
    """
    POST /api/client_update/ack
    payload: { "number": 52, "id": 123 }

    Записывает подтверждение, что бот number уже отработал обновление по событию id.
    """
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")
    update_id = data.get("id") or data.get("update_id")

    if number is None or update_id is None:
        return jsonify({"ok": False, "error": "number and id required"}), 400

    try:
        number_int = int(number)
        update_id_int = int(update_id)
    except Exception:
        return jsonify({"ok": False, "error": "bad number/id"}), 400

    update_row = ClientUpdate.query.get(update_id_int)
    if not update_row:
        return jsonify({"ok": False, "error": "update event not found"}), 404

    rng = NumberRange.query.get(update_row.range_id)
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    total = int(rng.end) - int(rng.start) + 1
    if total <= 0:
        return jsonify({"ok": False, "error": "empty range"}), 400

    rel = number_int - int(rng.start)
    if rel < 0 or rel >= total:
        return jsonify({"ok": False, "error": "number not in range"}), 400

    group_index = rel // 5
    if int(group_index) != int(update_row.group_index):
        return jsonify({"ok": False, "error": "wrong group"}), 400

    group_numbers = _client_update_group_numbers(rng, group_index)

    # пишем ack один раз
    exists = ClientUpdateAck.query.filter_by(update_id=update_row.id, number=number_int).first()
    if not exists:
        ack = ClientUpdateAck(
            update_id=update_row.id,
            number=number_int,
            ack_at=datetime.utcnow(),
        )
        db.session.add(ack)
        db.session.commit()

    done, acked_numbers = _client_update_is_done(update_row, group_numbers)

    return jsonify({
        "ok": True,
        "id": update_row.id,
        "group_index": update_row.group_index,
        "done": bool(done),
        "acked": len(acked_numbers),
        "total": len(group_numbers),
    })

# ====== API ДЛЯ ИГРОВОЙ ЛОГИКИ (СТОРОНА, ПОЗИЦИИ, WIN/LOOSE) ======
@app.route("/api/game/config", methods=["POST"])
def api_game_config():
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")
    side = (data.get("side") or "").strip()

    if number is None or side not in ("svet", "tma"):
        return jsonify({"ok": False, "error": "number and side required"}), 400

    try:
        number_int = int(number)
    except Exception:
        return jsonify({"ok": False, "error": "bad number"}), 400

    rng = (
        NumberRange.query
        .filter(NumberRange.start <= number_int, NumberRange.end >= number_int)
        .first()
    )
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    numbers = list(range(rng.start, rng.end + 1))
    total = len(numbers)
    if total <= 0:
        return jsonify({"ok": False, "error": "empty range"}), 400

    rel = number_int - rng.start
    if rel < 0 or rel >= total:
        return jsonify({"ok": False, "error": "number not in range"}), 400

    # разбиваем диапазон по пятёркам: [start..start+4], [start+5..start+9], ...
    group_index = rel // 5  # 0,1,...
    index_in_group = rel % 5

    group_start = group_index * 5
    group_numbers = numbers[group_start:group_start + 5]
    if not group_numbers:
        group_numbers = [number_int]

    # название группы для UI и win/lose (для 51-60 будет "left"/"right")
    group = "left" if group_index == 0 else "right"

    # какая группа сейчас играет на победу
    win_group = rng.win_group or "right"
    play_for_win = (group == win_group)

    games_completed = rng.games_completed or 0

    # выдаём позицию 1..5 по стороне для текущей игры
    game_index = int(rng.games_completed or 0)
    bucket = _get_game_bucket(rng.id, game_index)
    position = _assign_position(bucket, number_int, side)
    _cleanup_old_game_buckets(rng.id)

    # сохраняем состояние в AccountState (сторона, позиция, режим)
    now = datetime.utcnow()
    rows = (
        AccountState.query
        .filter_by(range_id=rng.id, number=number_int)
        .all()
    )
    if not rows:
        row = AccountState(
            range_id=rng.id,
            number=number_int,
            steam_id="unknown",
            last_update=now,
        )
        db.session.add(row)
        rows = [row]

    for r in rows:
        r.last_update = now
        r.side = side
        r.last_position = position
        r.last_play_for_win = play_for_win

    games_played = max((r.games_played or 0) for r in rows)
    db.session.commit()

    return jsonify({
        "ok": True,
        "config": {
            "number": number_int,
            "side": side,
            "group": group,
            "play_for_win": bool(play_for_win),
            "position": position,
            "games_played": int(games_played),
            "games_completed": int(games_completed),
            "win_group": win_group,
        },
    })


@app.route("/api/game/finished", methods=["POST"])
def api_game_finished():
    data = request.get_json(force=True, silent=True) or {}
    number = data.get("number")

    if number is None:
        return jsonify({"ok": False, "error": "number required"}), 400

    try:
        number_int = int(number)
    except Exception:
        return jsonify({"ok": False, "error": "bad number"}), 400

    rng = (
        NumberRange.query
        .filter(NumberRange.start <= number_int, NumberRange.end >= number_int)
        .first()
    )
    if not rng:
        return jsonify({"ok": False, "error": "range not found"}), 404

    now = datetime.utcnow()
    rows = (
        AccountState.query
        .filter_by(range_id=rng.id, number=number_int)
        .all()
    )
    if not rows:
        row = AccountState(
            range_id=rng.id,
            number=number_int,
            steam_id="unknown",
            last_update=now,
        )
        db.session.add(row)
        rows = [row]

    for r in rows:
        r.games_played = (r.games_played or 0) + 1
        r.last_update = now

    # мастер — первый номер диапазона; только он переключает WIN/LOOSE
    is_master = (number_int == rng.start)
    if is_master:
        rng.games_completed = (rng.games_completed or 0) + 1
        win_group = rng.win_group or "right"
        rng.win_group = "left" if win_group == "right" else "right"

        # очистим bucket позиций для завершённой игры
        finished_game_index = int(rng.games_completed or 0) - 1
        _GAME_POSITIONS.pop((int(rng.id), int(finished_game_index)), None)
        _cleanup_old_game_buckets(rng.id)

    db.session.commit()

    return jsonify({
        "ok": True,
        "is_master": is_master,
        "games_completed": rng.games_completed,
        "win_group": rng.win_group,
    })


# ====== CLI ======
@app.cli.command("init-db")
def init_db():
    ensure_schema()
    print("База создана/обновлена.")


@app.cli.command("create-admin")
def create_admin():
    ensure_schema()
    username = "tek1"
    password = "Kolya777"

    user = User.query.filter_by(username=username).first()
    if user:
        changed = False
        if not user.is_admin:
            user.is_admin = True
            changed = True
        if not user.is_super_admin:
            user.is_super_admin = True
            changed = True
        if changed:
            db.session.commit()
            print(f"Пользователь {username} повышен до super-admin (пароль не менял).")
        else:
            print("Super-admin уже существует.")
        return

    user = User(
        username=username,
        password_hash=generate_password_hash(password),
        is_admin=True,
        is_super_admin=True,
    )
    db.session.add(user)
    db.session.commit()
    print(f"Создан super-admin {username}/{password}")


if __name__ == "__main__":
    with app.app_context():
        ensure_schema()
    app.run(host="0.0.0.0", port=5000, debug=False)

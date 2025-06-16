from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user

def check_rights(required_rights):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Требуется авторизация", "danger")
                return redirect(url_for('login'))
            if current_user.role.name not in required_rights:
                flash("Недостаточно прав", "danger")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapper
    return decorator
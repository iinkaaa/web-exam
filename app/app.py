from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from models import db, User, Role, Equipment, Category, MaintenanceHistory, ResponsiblePersons, WriteOff, Photo
import os
import hashlib
from werkzeug.utils import secure_filename

app = Flask(__name__)
application = app
basedir = os.path.abspath(os.path.dirname(__file__))
app.secret_key = 'key' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'instance', 'users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Для доступа к этой странице необходимо авторизоваться'
login_manager.login_message_category = 'warning'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', type=int)
    status = request.args.get('status', type=str)
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')

    query = Equipment.query

    if category:
        query = query.filter(Equipment.category_id == category)
    if status:
        query = query.filter(Equipment.status == status)
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            query = query.filter(Equipment.purchase_date >= date_from_obj)
        except ValueError:
            pass
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            query = query.filter(Equipment.purchase_date <= date_to_obj)
        except ValueError:
            pass

    query = query.order_by(Equipment.purchase_date.desc())
    pagination = query.paginate(page=page, per_page=10, error_out=False)
    equipment_list = []
    for eq in pagination.items:
        equipment_list.append({
            'id': eq.id,
            'name': eq.name,
            'inventory_number': eq.inventory_number,
            'category_name': eq.category.name if eq.category_id else '',
            'status_display': eq.status,
        })

    categories = Category.query.all()
    return render_template('index.html',
        equipment_list=equipment_list,
        categories=categories,
        pagination=pagination)

def seed_test_data():
    if not Role.query.first():
        admin_role = Role(name='admin', description='Администратор')
        tech_role = Role(name='tech', description='Технический специалист')
        user_role = Role(name='user', description='Пользователь')
        db.session.add_all([admin_role, tech_role, user_role])
        db.session.commit()
    else:
        admin_role = Role.query.filter_by(name='admin').first()
        tech_role = Role.query.filter_by(name='tech').first()
        user_role = Role.query.filter_by(name='user').first()

    if not User.query.first():
        admin = User(
            username='admin',
            password_hash=generate_password_hash('admin123'),
            last_name='Иванов',
            first_name='Админ',
            middle_name='Админович',
            role_id=admin_role.id
        )
        tech = User(
            username='tech',
            password_hash=generate_password_hash('tech12345'),
            last_name='Петров',
            first_name='Техник',
            middle_name='Техничевич',
            role_id=tech_role.id
        )
        user = User(
            username='user',
            password_hash=generate_password_hash('user12345'),
            last_name='Сидоров',
            first_name='Пользователь',
            middle_name='Пользователевич',
            role_id=user_role.id
        )
        db.session.add_all([admin, tech, user])
        db.session.commit()

    if not Category.query.first():
        cat1 = Category(name='Компьютеры', description='Компьютерная техника')
        cat2 = Category(name='Принтеры', description='Печатающие устройства')
        cat3 = Category(name='Сканеры', description='Сканирующие устройства')
        db.session.add_all([cat1, cat2, cat3])
        db.session.commit()
    if not Equipment.query.first():
        eq1 = Equipment(
            name='Lenovo ThinkCentre',
            inventory_number='INV-001',
            category_id=Category.query.filter_by(name='Компьютеры').first().id,
            purchase_date=datetime(2022, 5, 10),
            cost=45000,
            status='В эксплуатации',
            note='Рабочая станция бухгалтера'
        )
        eq2 = Equipment(
            name='HP LaserJet 1020',
            inventory_number='INV-002',
            category_id=Category.query.filter_by(name='Принтеры').first().id,
            purchase_date=datetime(2021, 3, 15),
            cost=12000,
            status='На ремонте',
            note='Требуется замена картриджа'
        )
        eq3 = Equipment(
            name='Canon CanoScan LiDE 300',
            inventory_number='INV-003',
            category_id=Category.query.filter_by(name='Сканеры').first().id,
            purchase_date=datetime(2020, 8, 20),
            cost=7000,
            status='Списано',
            note='Не включается'
        )
        db.session.add_all([eq1, eq2, eq3])
        db.session.commit()
        

with app.app_context():
    db.drop_all()
    db.create_all()
    seed_test_data()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=remember)
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль', 'danger')
    return render_template('login.html',  title='Авторизация')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    roles = Role.query.all()
    
    if request.method == 'POST':
        form_data = {
            'username': request.form.get('username', '').strip(),
            'last_name': request.form.get('last_name', '').strip(),
            'first_name': request.form.get('first_name', '').strip(),
            'middle_name': request.form.get('middle_name', '').strip(),
            'role_id': request.form.get('role_id', '')
        }
        
        password = request.form.get('password', '').strip()
        errors = {}
        
        
        if not form_data['username']:
            errors['username'] = 'Логин обязателен'
        elif len(form_data['username']) < 5:
            errors['username'] = 'Логин должен быть не менее 5 символов'
        elif not form_data['username'].isalnum():
            errors['username'] = 'Логин должен содержать только латинские буквы и цифры'
        
        
        if not password:
            errors['password'] = 'Пароль обязателен'
        else:
            pass_error = validate_password(password)
            if pass_error:
                errors['password'] = pass_error
        
        
        if not form_data['first_name']:
            errors['first_name'] = 'Обязательное поле'
        
        if errors:
            return render_template('create_user.html',
                                roles=roles,
                                form_data=form_data,
                                errors=errors)
        
        try:
            user = User(
                username=form_data['username'],
                password_hash=generate_password_hash(password),
                last_name=form_data['last_name'] or None,
                first_name=form_data['first_name'],
                middle_name=form_data['middle_name'] or None,
                role_id=int(form_data['role_id']) if form_data['role_id'] else None
            )
            db.session.add(user)
            db.session.commit()
            flash('Пользователь успешно создан!', 'success')
            return redirect(url_for('index'))
        
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка базы данных: {str(e)}', 'danger')
            return render_template('create_user.html',
                                roles=roles,
                                form_data=form_data,
                                errors={})

    return render_template('create_user.html',
                         roles=roles,
                         form_data={},
                         errors={})

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def calculate_md5(file):
    md5_hash = hashlib.md5()
    for chunk in iter(lambda: file.read(4096), b""):
        md5_hash.update(chunk)
    file.seek(0)
    return md5_hash.hexdigest()

@app.route('/equipment/<int:id>')
def view_equipment(id):
    equipment = Equipment.query.get_or_404(id)
    return render_template('view_equipment.html', equipment=equipment)

@app.route('/equipment/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_equipment(id):
    if not current_user.role.name == 'admin':
        flash('У вас недостаточно прав для выполнения данного действия', 'danger')
        return redirect(url_for('index'))

    equipment = Equipment.query.get_or_404(id)
    categories = Category.query.all()

    if request.method == 'POST':
        form_data = {
            'name': request.form.get('name', '').strip(),
            'inventory_number': request.form.get('inventory_number', '').strip(),
            'category_id': request.form.get('category_id'),
            'purchase_date': request.form.get('purchase_date'),
            'cost': request.form.get('cost'),
            'status': request.form.get('status'),
            'note': request.form.get('note', '').strip()
        }

        errors = {}

        if not form_data['name']:
            errors['name'] = 'Название обязательно'
        
        if not form_data['inventory_number']:
            errors['inventory_number'] = 'Инвентарный номер обязателен'
        else:
            # Проверка уникальности инвентарного номера
            existing = Equipment.query.filter(
                Equipment.inventory_number == form_data['inventory_number'],
                Equipment.id != id
            ).first()
            if existing:
                errors['inventory_number'] = 'Инвентарный номер уже используется'

        if not form_data['category_id']:
            errors['category_id'] = 'Выберите категорию'

        if not form_data['purchase_date']:
            errors['purchase_date'] = 'Дата покупки обязательна'
        else:
            try:
                purchase_date = datetime.strptime(form_data['purchase_date'], '%Y-%m-%d').date()
            except ValueError:
                errors['purchase_date'] = 'Неверный формат даты'

        if not form_data['cost']:
            errors['cost'] = 'Стоимость обязательна'
        else:
            try:
                cost = float(form_data['cost'])
                if cost < 0:
                    errors['cost'] = 'Стоимость не может быть отрицательной'
            except ValueError:
                errors['cost'] = 'Неверный формат стоимости'

        if not form_data['status']:
            errors['status'] = 'Выберите статус'

        # Обработка фотографии
        photo = request.files.get('photo')
        if photo and photo.filename:
            if not allowed_file(photo.filename):
                errors['photo'] = 'Недопустимый формат файла'
            else:
                # Проверка MD5-хэша
                md5_hash = calculate_md5(photo)
                existing_photo = Photo.query.filter_by(md5_hash=md5_hash).first()
                
                if existing_photo:
                    # Проверяем, не используется ли фото другим оборудованием
                    other_equipment = Equipment.query.join(Equipment.photos).filter(
                        Photo.id == existing_photo.id,
                        Equipment.id != id
                    ).first()
                    
                    if other_equipment:
                        errors['photo'] = 'Это фото уже используется другим оборудованием'
                    else:
                        # Используем существующую фотографию
                        equipment.photos = [existing_photo]
                else:
                    # Сохраняем новую фотографию
                    filename = secure_filename(photo.filename)
                    photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    
                    # Проверяем, не существует ли файл с таким именем
                    if os.path.exists(photo_path):
                        base, ext = os.path.splitext(filename)
                        filename = f"{base}_{int(datetime.now().timestamp())}{ext}"
                        photo_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    
                    photo.save(photo_path)
                    
                    new_photo = Photo(
                        filename=filename,
                        mime_type=photo.content_type,
                        md5_hash=md5_hash,
                        equipment_id=equipment.id
                    )
                    db.session.add(new_photo)

        if errors:
            return render_template('edit_equipment.html',
                                equipment=equipment,
                                categories=categories,
                                form_data=form_data,
                                errors=errors)

        try:
            # Обновление данных оборудования
            equipment.name = form_data['name']
            equipment.inventory_number = form_data['inventory_number']
            equipment.category_id = int(form_data['category_id'])
            equipment.purchase_date = datetime.strptime(form_data['purchase_date'], '%Y-%m-%d').date()
            equipment.cost = float(form_data['cost'])
            equipment.status = form_data['status']
            equipment.note = form_data['note']

            db.session.commit()
            flash('Оборудование успешно обновлено', 'success')
            return redirect(url_for('view_equipment', id=equipment.id))

        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при сохранении данных: {str(e)}', 'danger')
            return render_template('edit_equipment.html',
                                equipment=equipment,
                                categories=categories,
                                form_data=form_data,
                                errors={})

    return render_template('edit_equipment.html',
                         equipment=equipment,
                         categories=categories)

@app.route('/equipment/<int:id>/delete', methods=['POST'])
@login_required
def delete_equipment(id):
    if not current_user.role.name == 'admin':
        flash('У вас недостаточно прав для выполнения данного действия', 'danger')
        return redirect(url_for('index'))
    
    equipment = Equipment.query.get_or_404(id)
    
    try:
        for photo in equipment.photos:
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo.filename)
            if os.path.exists(photo_path):
                os.remove(photo_path)
        
        db.session.delete(equipment)
        db.session.commit()
        flash('Оборудование успешно удалено', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при удалении оборудования: {str(e)}', 'danger')
    
    return redirect(url_for('index'))

import re

def validate_password(password):
    if len(password) < 8:
        return "Пароль должен быть не менее 8 символов"
    if not re.search(r'[A-ZА-Я]', password):
        return "Пароль должен содержать хотя бы одну заглавную букву"
    if not re.search(r'[a-zа-я]', password):
        return "Пароль должен содержать хотя бы одну строчную букву"
    if not re.search(r'\d', password):
        return "Пароль должен содержать хотя бы одну цифру"
    if ' ' in password:
        return "Пароль не должен содержать пробелов"
    return None


@app.route('/equipment/<int:id>/maintenance', methods=['POST'])
@login_required
def add_maintenance(id):
    if not current_user.role.name == 'tech':
        flash('У вас недостаточно прав для выполнения данного действия', 'danger')
        return redirect(url_for('index'))

    equipment = Equipment.query.get_or_404(id)
    
    form_data = {
        'maintenance_type': request.form.get('maintenance_type', '').strip(),
        'comment': request.form.get('comment', '').strip()
    }

    errors = {}

    if not form_data['maintenance_type']:
        errors['maintenance_type'] = 'Выберите тип обслуживания'

    if not form_data['comment']:
        errors['comment'] = 'Введите комментарий'

    if errors:
        return render_template('view_equipment.html',
                            equipment=equipment,
                            form_data=form_data,
                            errors=errors)

    try:
        maintenance = MaintenanceHistory(
            equipment_id=equipment.id,
            maintenance_type=form_data['maintenance_type'],
            comment=form_data['comment'],
            date=datetime.utcnow().date()
        )
        db.session.add(maintenance)
        db.session.commit()
        flash('Запись об обслуживании успешно добавлена', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Ошибка при добавлении записи: {str(e)}', 'danger')

    return redirect(url_for('view_equipment', id=equipment.id))

@app.route('/maintenance', methods=['GET'])
@login_required
def maintenance():
    if current_user.role.name != 'tech':
        flash('У вас нет прав для добавления записей об обслуживании', 'danger')
        return redirect(url_for('index'))
    
    equipment_list = Equipment.query.all()
    equipment_id = request.args.get('id', type=int)
    equipment = Equipment.query.get(equipment_id) if equipment_id else None
    
    return render_template('maintenance.html', 
                         equipment_list=equipment_list,
                         equipment=equipment)



# app.register_blueprint(reports_bp)

# @app.before_request
# def log_visit():
#     if request.path.startswith('/static/'):
#         return
    
#     visit = VisitLog(
#         path=request.path,
#         user_id=current_user.id if current_user.is_authenticated else None
#     )
#     db.session.add(visit)
#     db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import check_password_hash
from flask_login import UserMixin

db = SQLAlchemy()

equipment_responsible = db.Table('equipment_responsible',
    db.Column('equipment_id', db.Integer, db.ForeignKey('equipment.id'), primary_key=True),
    db.Column('responsible_id', db.Integer, db.ForeignKey('responsible_persons.id'), primary_key=True)
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(50))
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', backref='users')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)

class Equipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    inventory_number = db.Column(db.String(50), unique=True, nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    purchase_date = db.Column(db.Date, nullable=False)
    cost = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.Enum('В эксплуатации', 'На ремонте', 'Списано', name='equipment_status'), nullable=False, default='В эксплуатации')
    note = db.Column(db.Text)
    photos = db.relationship('Photo', backref='equipment', lazy='dynamic', cascade='all, delete-orphan')
    maintenance_history = db.relationship('MaintenanceHistory', backref='equipment', cascade='all, delete-orphan')
    responsible_persons = db.relationship('ResponsiblePersons', secondary=equipment_responsible, back_populates='equipments')
    write_offs = db.relationship('WriteOff', backref='equipment_obj', cascade='all, delete-orphan')
    
class Photo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    md5_hash = db.Column(db.String(32), nullable=False)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)

class MaintenanceHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    maintenance_type = db.Column(db.String(100), nullable=False)
    comment = db.Column(db.Text)

class ResponsiblePersons(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    position = db.Column(db.String(100), nullable=False)
    contact_details = db.Column(db.Text)
    equipments = db.relationship('Equipment', secondary=equipment_responsible, 
                               back_populates='responsible_persons')

class WriteOff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    equipment_id = db.Column(db.Integer, db.ForeignKey('equipment.id'), nullable=False)
    write_off_date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    reason = db.Column(db.Text, nullable=False)
    act_filename = db.Column(db.String(100))
    act_mime_type = db.Column(db.String(100))
    act_md5_hash = db.Column(db.String(32))
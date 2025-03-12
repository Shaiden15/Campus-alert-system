from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager
from flask_migrate import Migrate
import sqlite3

db = SQLAlchemy()
DB_NAME = "database.db"


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'hjshjhdjah kjshkjdhjs'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    migrate = Migrate(app, db)
    db.init_app(app)
    

    from .views import views
    from .auth import auth

    app.register_blueprint(views, url_prefix='/')
    app.register_blueprint(auth, url_prefix='/')


    from .models import User, Note
    
    with app.app_context():
        db.create_all()

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        return User.query.get(int(id))

    return app


def create_database(app):
    if not path.exists('website/' + DB_NAME):
        db.create_all(app=app)
        print('Created Database!')


def store_image_path(image_path, db_path='database.db'):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS images (id INTEGER PRIMARY KEY, path TEXT)")
    cursor.execute("INSERT INTO images (path) VALUES (?)", (image_path,))
    conn.commit()
    conn.close()

store_image_path('path_to_your_image.jpg')

def retrieve_image_path(image_id, db_path='database.db'):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT path FROM images WHERE id=?", (image_id,))
    image_path = cursor.fetchone()[0]
    conn.close()
    return image_path

image_path = retrieve_image_path(1)
print(f"Image path: {image_path}")
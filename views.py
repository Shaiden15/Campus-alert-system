import os
import json
from flask import Blueprint, render_template, request, flash, jsonify, redirect, url_for
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from .models import Note
from . import db

views = Blueprint('views', __name__)

# Define the upload folder
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'Flask2.0', 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Ensure upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@views.route('/', methods=['GET', 'POST'])
@login_required
def home():
    if request.method == 'POST':
        note_text = request.form.get('note')
        file = request.files.get('file')

        if not note_text and not file:
            flash('Note or image required!', category='error')
        else:
            image_path = None
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                save_path = os.path.join(UPLOAD_FOLDER, filename)

                # Ensure the directory exists before saving
                os.makedirs(os.path.dirname(save_path), exist_ok=True)

                file.save(save_path)  # Save the image

                # Store the relative path for displaying in HTML
                image_path = f"uploads/{filename}"

            new_note = Note(data=note_text, user_id=current_user.id, image_path=image_path)
            db.session.add(new_note)
            db.session.commit()
            flash('Note added!', category='success')

            return redirect(url_for('views.home'))

    return render_template("home.html", user=current_user)

@views.route('/delete-note', methods=['POST'])
@login_required
def delete_note():
    note = json.loads(request.data)
    note_id = note.get('noteId')
    note = Note.query.get(note_id)
    if note:
        if note.user_id == current_user.id:
            db.session.delete(note)
            db.session.commit()
            flash("Note deleted!", category='success')

    return jsonify({})

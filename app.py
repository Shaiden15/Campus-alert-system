from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///campus_security.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='student')  # student, staff, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
class Disruption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # low, medium, high
    status = db.Column(db.String(20), nullable=False, default='pending')  # pending, verified, resolved, rejected
    reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    verified_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    reporter = db.relationship('User', foreign_keys=[reported_by], backref='reported_disruptions')
    verifier = db.relationship('User', foreign_keys=[verified_by], backref='verified_disruptions')

# Helper functions
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'danger')
            return redirect(url_for('login'))
        if session.get('role') not in ['admin', 'staff']:
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get recent disruptions for dashboard
    recent_disruptions = Disruption.query.filter(
        Disruption.status.in_(['verified', 'pending'])
    ).order_by(Disruption.created_at.desc()).limit(5).all()
    
    # Get counts for dashboard stats
    active_count = Disruption.query.filter_by(status='verified').count()
    resolved_count = Disruption.query.filter_by(status='resolved').count()
    total_count = Disruption.query.count()
    
    return render_template('dashboard.html', 
                          recent_disruptions=recent_disruptions,
                          active_count=active_count,
                          resolved_count=resolved_count,
                          total_count=total_count)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'student')
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/report-disruption', methods=['GET', 'POST'])
@login_required
def report_disruption():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        location = request.form.get('location')
        severity = request.form.get('severity')
        
        new_disruption = Disruption(
            title=title,
            description=description,
            location=location,
            severity=severity,
            reported_by=session['user_id']
        )
        
        db.session.add(new_disruption)
        db.session.commit()
        
        flash('Disruption reported successfully! It will be reviewed by campus security.', 'success')
        return redirect(url_for('index'))
    
    return render_template('report_disruption.html')

@app.route('/current-disruptions')
@login_required
def current_disruptions():
    disruptions = Disruption.query.filter_by(status='verified').order_by(Disruption.created_at.desc()).all()
    return render_template('current_disruptions.html', disruptions=disruptions)

@app.route('/past-disruptions')
@login_required
def past_disruptions():
    disruptions = Disruption.query.filter_by(status='resolved').order_by(Disruption.created_at.desc()).all()
    return render_template('past_disruptions.html', disruptions=disruptions)

@app.route('/verify-disruptions')
@admin_required
def verify_disruptions():
    pending_disruptions = Disruption.query.filter_by(status='pending').order_by(Disruption.created_at.desc()).all()
    return render_template('verify_disruptions.html', disruptions=pending_disruptions)

@app.route('/verify-disruption/<int:disruption_id>', methods=['POST'])
@admin_required
def verify_disruption(disruption_id):
    disruption = Disruption.query.get_or_404(disruption_id)
    action = request.form.get('action')
    
    if action == 'verify':
        disruption.status = 'verified'
        disruption.verified_by = session['user_id']
        disruption.updated_at = datetime.utcnow()
        
        # Send email notification
        send_disruption_notification(disruption)
        
        flash('Disruption verified and notification sent successfully!', 'success')
    elif action == 'reject':
        disruption.status = 'rejected'
        disruption.updated_at = datetime.utcnow()
        flash('Disruption rejected.', 'info')
    elif action == 'resolve':
        disruption.status = 'resolved'
        disruption.updated_at = datetime.utcnow()
        flash('Disruption marked as resolved.', 'success')
    
    db.session.commit()
    
    # Determine where to redirect based on the referrer
    if request.referrer and 'verify-disruptions' in request.referrer:
        return redirect(url_for('verify_disruptions'))
    elif request.referrer and 'disruption' in request.referrer:
        return redirect(url_for('view_disruption', disruption_id=disruption.id))
    else:
        return redirect(url_for('index'))

@app.route('/disruption/<int:disruption_id>')
@login_required
def view_disruption(disruption_id):
    disruption = Disruption.query.get_or_404(disruption_id)
    return render_template('view_disruption.html', disruption=disruption)

# Create database tables
with app.app_context():
    db.create_all()
    
    # Create admin user if not exists
    admin = User.query.filter_by(email='admin@dut.ac.za').first()
    if not admin:
        admin_password = generate_password_hash('admin123')
        admin = User(username='Admin', email='admin@dut.ac.za', password=admin_password, role='admin')
        db.session.add(admin)
        
        # Create staff user if not exists
        staff = User.query.filter_by(email='staff@dut.ac.za').first()
        if not staff:
            staff_password = generate_password_hash('staff123')
            staff = User(username='Staff Member', email='staff@dut.ac.za', password=staff_password, role='staff')
            db.session.add(staff)
        
        # Create student user if not exists
        student = User.query.filter_by(email='student@dut.ac.za').first()
        if not student:
            student_password = generate_password_hash('student123')
            student = User(username='Student', email='student@dut.ac.za', password=student_password, role='student')
            db.session.add(student)
        
        db.session.commit()
            
            for disruption_data in sample_disruptions:
                disruption = Disruption(**disruption_data)
                db.session.add(disruption)
            
            db.session.commit()

if __name__ == '__main__':
    app.run(debug=True)

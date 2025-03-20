from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import uuid
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///unisafe.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max upload size
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png'}

# Create upload folder if it doesn't exist
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'disruptions'), exist_ok=True)

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  username = db.Column(db.String(100), unique=True, nullable=False)
  email = db.Column(db.String(100), unique=True, nullable=False)
  password = db.Column(db.String(200), nullable=False)
  first_name = db.Column(db.String(100), nullable=False)
  last_name = db.Column(db.String(100), nullable=False)
  date_of_birth = db.Column(db.Date, nullable=True)
  contact_number = db.Column(db.String(20), nullable=True)
  profile_picture = db.Column(db.String(200), nullable=True, default='default_profile.png')
  role = db.Column(db.String(20), nullable=False, default='student')  # student, staff, admin, security
  created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Campus(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  name = db.Column(db.String(100), unique=True, nullable=False)

class SecurityTeam(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  campus_id = db.Column(db.Integer, db.ForeignKey('campus.id'), nullable=False)
  severity_level = db.Column(db.String(20), nullable=False)  # low, medium, high
  
  campus = db.relationship('Campus', backref='security_teams')
  
  __table_args__ = (db.UniqueConstraint('campus_id', 'severity_level', name='unique_campus_severity'),)

class SecurityTeamMember(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  team_id = db.Column(db.Integer, db.ForeignKey('security_team.id'), nullable=False)
  
  user = db.relationship('User', backref='security_teams')
  team = db.relationship('SecurityTeam', backref='members')

class Disruption(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String(100), nullable=False)
  description = db.Column(db.Text, nullable=False)
  location = db.Column(db.String(100), nullable=False)
  campus_id = db.Column(db.Integer, db.ForeignKey('campus.id'), nullable=False)
  severity = db.Column(db.String(20), nullable=False)  # low, medium, high
  status = db.Column(db.String(20), nullable=False, default='pending')  # pending, assigned, verified, resolved, rejected
  reported_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  verified_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
  assigned_team_id = db.Column(db.Integer, db.ForeignKey('security_team.id'), nullable=True)
  created_at = db.Column(db.DateTime, default=datetime.utcnow)
  updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
  
  reporter = db.relationship('User', foreign_keys=[reported_by], backref='reported_disruptions')
  verifier = db.relationship('User', foreign_keys=[verified_by], backref='verified_disruptions')
  campus = db.relationship('Campus', backref='disruptions')
  assigned_team = db.relationship('SecurityTeam', backref='assigned_disruptions')
  
class DisruptionImage(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  disruption_id = db.Column(db.Integer, db.ForeignKey('disruption.id'), nullable=False)
  filename = db.Column(db.String(200), nullable=False)
  uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
  
  disruption = db.relationship('Disruption', backref='images')

class SecurityReport(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  disruption_id = db.Column(db.Integer, db.ForeignKey('disruption.id'), nullable=False)
  security_officer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
  is_valid = db.Column(db.Boolean, nullable=False)
  actual_location = db.Column(db.String(100), nullable=False)
  actual_severity = db.Column(db.String(20), nullable=False)  # low, medium, high
  actions_taken = db.Column(db.Text, nullable=False)
  reported_at = db.Column(db.DateTime, default=datetime.utcnow)
  
  disruption = db.relationship('Disruption', backref='security_reports')
  security_officer = db.relationship('User', backref='submitted_reports')

# Helper functions
def allowed_file(filename):
  return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_file(file, folder):
  if file and allowed_file(file.filename):
      filename = secure_filename(file.filename)
      # Generate unique filename to prevent overwriting
      unique_filename = f"{uuid.uuid4().hex}_{filename}"
      file_path = os.path.join(app.config['UPLOAD_FOLDER'], folder, unique_filename)
      file.save(file_path)
      return os.path.join(folder, unique_filename)
  return None

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
      if session.get('role') != 'admin':
          flash('You do not have permission to access this page', 'danger')
          return redirect(url_for('index'))
      return f(*args, **kwargs)
  return decorated_function

def staff_required(f):
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

def security_required(f):
  @wraps(f)
  def decorated_function(*args, **kwargs):
      if 'user_id' not in session:
          flash('Please login to access this page', 'danger')
          return redirect(url_for('login'))
      if session.get('role') != 'security':
          flash('You do not have permission to access this page', 'danger')
          return redirect(url_for('index'))
      return f(*args, **kwargs)
  return decorated_function

def send_email_notification(recipient_email, subject, message):
  # This is a placeholder for email functionality
  # In a real application, you would use a library like Flask-Mail
  print(f"Sending email to {recipient_email}")
  print(f"Subject: {subject}")
  print(f"Message: {message}")
  # Return True to simulate successful email sending
  return True

# Routes
@app.route('/')
def index():
  if 'user_id' not in session:
      return redirect(url_for('login'))
  
  # Get recent disruptions for dashboard
  recent_disruptions = Disruption.query.filter(
      Disruption.status.in_(['verified', 'assigned', 'pending'])
  ).order_by(Disruption.created_at.desc()).limit(5).all()
  
  # Get counts for dashboard stats
  active_count = Disruption.query.filter(Disruption.status.in_(['verified', 'assigned'])).count()
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
          session['profile_picture'] = user.profile_picture
          
          flash('Login successful!', 'success')
          
          # Redirect based on role
          if user.role == 'security':
              return redirect(url_for('security_dashboard'))
          else:
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
      first_name = request.form.get('first_name')
      last_name = request.form.get('last_name')
      date_of_birth = request.form.get('date_of_birth')
      contact_number = request.form.get('contact_number')
      role = request.form.get('role')
      
      # Only allow student and staff registrations
      if role not in ['student', 'staff']:
          flash('Invalid role selection', 'danger')
          return redirect(url_for('register'))
      
      # Check if email already exists
      existing_user = User.query.filter_by(email=email).first()
      if existing_user:
          flash('Email already registered', 'danger')
          return redirect(url_for('register'))
      
      # Check if username already exists
      existing_username = User.query.filter_by(username=username).first()
      if existing_username:
          flash('Username already taken', 'danger')
          return redirect(url_for('register'))
      
      # Process profile picture if uploaded
      profile_picture = 'default_profile.png'
      if 'profile_picture' in request.files:
          file = request.files['profile_picture']
          if file.filename != '':
              saved_file = save_file(file, 'profiles')
              if saved_file:
                  profile_picture = saved_file
      
      # Create new user
      hashed_password = generate_password_hash(password)
      
      # Convert date string to date object
      dob = None
      if date_of_birth:
          try:
              dob = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
          except ValueError:
              flash('Invalid date format', 'danger')
              return redirect(url_for('register'))
      
      new_user = User(
          username=username,
          email=email,
          password=hashed_password,
          first_name=first_name,
          last_name=last_name,
          date_of_birth=dob,
          contact_number=contact_number,
          profile_picture=profile_picture,
          role=role
      )
      
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

@app.route('/profile')
@login_required
def profile():
  user = User.query.get(session['user_id'])
  return render_template('profile.html', user=user)

@app.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
  user = User.query.get(session['user_id'])
  
  if request.method == 'POST':
      user.first_name = request.form.get('first_name')
      user.last_name = request.form.get('last_name')
      user.contact_number = request.form.get('contact_number')
      
      # Process date of birth
      date_of_birth = request.form.get('date_of_birth')
      if date_of_birth:
          try:
              user.date_of_birth = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
          except ValueError:
              flash('Invalid date format', 'danger')
              return redirect(url_for('edit_profile'))
      
      # Process profile picture if uploaded
      if 'profile_picture' in request.files:
          file = request.files['profile_picture']
          if file.filename != '':
              saved_file = save_file(file, 'profiles')
              if saved_file:
                  # Delete old profile picture if it's not the default
                  if user.profile_picture != 'default_profile.png':
                      try:
                          old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], user.profile_picture)
                          if os.path.exists(old_file_path):
                              os.remove(old_file_path)
                      except Exception as e:
                          print(f"Error deleting old profile picture: {e}")
                  
                  user.profile_picture = saved_file
                  session['profile_picture'] = saved_file
      
      db.session.commit()
      flash('Profile updated successfully!', 'success')
      return redirect(url_for('profile'))
  
  return render_template('edit_profile.html', user=user)

@app.route('/report-disruption', methods=['GET', 'POST'])
@login_required
def report_disruption():
  campuses = Campus.query.all()
  
  if request.method == 'POST':
      title = request.form.get('title')
      description = request.form.get('description')
      location = request.form.get('location')
      campus_id = request.form.get('campus_id')
      severity = request.form.get('severity')
      
      # Create new disruption
      new_disruption = Disruption(
          title=title,
          description=description,
          location=location,
          campus_id=campus_id,
          severity=severity,
          reported_by=session['user_id']
      )
      
      db.session.add(new_disruption)
      db.session.commit()
      
      # Process uploaded images (up to 5)
      files = request.files.getlist('images')
      image_count = 0
      
      for file in files:
          if image_count >= 5:
              break
              
          if file and file.filename != '':
              saved_file = save_file(file, 'disruptions')
              if saved_file:
                  new_image = DisruptionImage(
                      disruption_id=new_disruption.id,
                      filename=saved_file
                  )
                  db.session.add(new_image)
                  image_count += 1
      
      if image_count > 0:
          db.session.commit()
      
      flash('Disruption reported successfully! It will be reviewed by campus security.', 'success')
      return redirect(url_for('index'))
  
  return render_template('report_disruption.html', campuses=campuses)

@app.route('/current-disruptions')
@login_required
def current_disruptions():
  disruptions = Disruption.query.filter(
      Disruption.status.in_(['verified', 'assigned'])
  ).order_by(Disruption.created_at.desc()).all()
  
  return render_template('current_disruptions.html', disruptions=disruptions)

@app.route('/past-disruptions')
@login_required
def past_disruptions():
  disruptions = Disruption.query.filter(
      Disruption.status.in_(['resolved', 'rejected'])
  ).order_by(Disruption.created_at.desc()).all()
  
  return render_template('past_disruptions.html', disruptions=disruptions)

@app.route('/disruption/<int:disruption_id>')
@login_required
def view_disruption(disruption_id):
  disruption = Disruption.query.get_or_404(disruption_id)
  security_report = None
  
  if disruption.status in ['verified', 'resolved']:
      security_report = SecurityReport.query.filter_by(disruption_id=disruption.id).first()
  
  return render_template('view_disruption.html', disruption=disruption, security_report=security_report)

@app.route('/verify-disruptions')
@staff_required
def verify_disruptions():
  pending_disruptions = Disruption.query.filter_by(status='pending').order_by(Disruption.created_at.desc()).all()
  security_teams = SecurityTeam.query.all()
  
  return render_template('verify_disruptions.html', 
                        disruptions=pending_disruptions,
                        security_teams=security_teams)

# Add this route to handle individual disruption verification
@app.route('/verify-disruption/<int:disruption_id>', methods=['POST'])
@staff_required
def verify_disruption(disruption_id):
    disruption = Disruption.query.get_or_404(disruption_id)
    action = request.form.get('action')
    
    if action == 'verify':
        disruption.status = 'verified'
        disruption.verified_by = session['user_id']
        flash('Disruption verified successfully!', 'success')
    elif action == 'reject':
        disruption.status = 'rejected'
        disruption.verified_by = session['user_id']
        flash('Disruption rejected successfully!', 'danger')
    elif action == 'resolve':
        disruption.status = 'resolved'
        flash('Disruption marked as resolved successfully!', 'success')
    
    disruption.updated_at = datetime.utcnow()
    db.session.commit()
    
    # Notify the reporter
    reporter = User.query.get(disruption.reported_by)
    if reporter:
        status_text = disruption.status.capitalize()
        subject = f"Your Disruption Report has been {status_text}"
        message = f"""
        Dear {reporter.first_name},
        
        Your disruption report "{disruption.title}" has been {status_text.lower()} by our staff.
        
        Thank you for using UniSafe.
        
        Regards,
        UniSafe Team
        """
        send_email_notification(reporter.email, subject, message)
    
    return redirect(url_for('verify_disruptions'))

@app.route('/assign-disruption/<int:disruption_id>', methods=['POST'])
@staff_required
def assign_disruption(disruption_id):
  disruption = Disruption.query.get_or_404(disruption_id)
  team_id = request.form.get('team_id')
  
  if not team_id:
      flash('Please select a security team', 'danger')
      return redirect(url_for('verify_disruptions'))
  
  team = SecurityTeam.query.get(team_id)
  if not team:
      flash('Invalid security team', 'danger')
      return redirect(url_for('verify_disruptions'))
  
  disruption.status = 'assigned'
  disruption.assigned_team_id = team.id
  disruption.updated_at = datetime.utcnow()
  
  db.session.commit()
  
  # Notify security team members
  team_members = SecurityTeamMember.query.filter_by(team_id=team.id).all()
  for member in team_members:
      security_officer = User.query.get(member.user_id)
      if security_officer:
          subject = f"New Disruption Assignment: {disruption.title}"
          message = f"""
          Dear {security_officer.first_name},
          
          A new disruption has been assigned to your team:
          
          Title: {disruption.title}
          Location: {disruption.location}
          Campus: {disruption.campus.name}
          Severity: {disruption.severity}
          
          Please check your dashboard for more details.
          
          Regards,
          UniSafe Team
          """
          send_email_notification(security_officer.email, subject, message)
  
  flash('Disruption assigned to security team successfully!', 'success')
  return redirect(url_for('verify_disruptions'))

@app.route('/security/dashboard')
@security_required
def security_dashboard():
  # Get security officer's teams
  user_id = session['user_id']
  team_memberships = SecurityTeamMember.query.filter_by(user_id=user_id).all()
  team_ids = [tm.team_id for tm in team_memberships]
  
  # Get assigned disruptions for these teams
  assigned_disruptions = Disruption.query.filter(
      Disruption.status == 'assigned',
      Disruption.assigned_team_id.in_(team_ids)
  ).order_by(Disruption.created_at.desc()).all()
  
  # Get recently verified disruptions by this security officer
  verified_disruptions = Disruption.query.filter(
      Disruption.status.in_(['verified', 'resolved']),
      Disruption.verified_by == user_id
  ).order_by(Disruption.updated_at.desc()).limit(5).all()
  
  return render_template('security_dashboard.html',
                        assigned_disruptions=assigned_disruptions,
                        verified_disruptions=verified_disruptions)

@app.route('/security/verify-disruption/<int:disruption_id>', methods=['GET', 'POST'])
@security_required
def security_verify_disruption(disruption_id):
  disruption = Disruption.query.get_or_404(disruption_id)
  
  # Check if the disruption is assigned to one of the security officer's teams
  user_id = session['user_id']
  team_memberships = SecurityTeamMember.query.filter_by(user_id=user_id).all()
  team_ids = [tm.team_id for tm in team_memberships]
  
  if disruption.assigned_team_id not in team_ids:
      flash('You do not have permission to verify this disruption', 'danger')
      return redirect(url_for('security_dashboard'))
  
  if request.method == 'POST':
      is_valid = request.form.get('is_valid') == 'yes'
      actual_location = request.form.get('actual_location')
      actual_severity = request.form.get('actual_severity')
      actions_taken = request.form.get('actions_taken')
      
      # Create security report
      new_report = SecurityReport(
          disruption_id=disruption.id,
          security_officer_id=user_id,
          is_valid=is_valid,
          actual_location=actual_location,
          actual_severity=actual_severity,
          actions_taken=actions_taken
      )
      
      db.session.add(new_report)
      
      # Update disruption status
      if is_valid:
          disruption.status = 'verified'
      else:
          disruption.status = 'rejected'
      
      disruption.verified_by = user_id
      disruption.updated_at = datetime.utcnow()
      
      db.session.commit()
      
      # Notify the reporter
      reporter = User.query.get(disruption.reported_by)
      if reporter:
          status_text = "verified" if is_valid else "rejected"
          subject = f"Your Disruption Report has been {status_text}"
          message = f"""
          Dear {reporter.first_name},
          
          Your disruption report "{disruption.title}" has been {status_text} by our security team.
          
          {f"Actions taken: {actions_taken}" if is_valid else f"Reason: {actions_taken}"}
          
          Thank you for using UniSafe.
          
          Regards,
          UniSafe Team
          """
          send_email_notification(reporter.email, subject, message)
      
      flash(f'Disruption has been {"verified" if is_valid else "rejected"} successfully!', 'success')
      return redirect(url_for('security_dashboard'))
  
  return render_template('security_verify_disruption.html', disruption=disruption)

@app.route('/security/resolve-disruption/<int:disruption_id>', methods=['POST'])
@security_required
def security_resolve_disruption(disruption_id):
  disruption = Disruption.query.get_or_404(disruption_id)
  
  # Check if the disruption was verified by this security officer
  if disruption.verified_by != session['user_id']:
      flash('You do not have permission to resolve this disruption', 'danger')
      return redirect(url_for('security_dashboard'))
  
  disruption.status = 'resolved'
  disruption.updated_at = datetime.utcnow()
  
  db.session.commit()
  
  # Notify the reporter
  reporter = User.query.get(disruption.reported_by)
  if reporter:
      subject = "Your Disruption Report has been resolved"
      message = f"""
      Dear {reporter.first_name},
      
      Your disruption report "{disruption.title}" has been resolved by our security team.
      
      Thank you for using UniSafe.
      
      Regards,
      UniSafe Team
      """
      send_email_notification(reporter.email, subject, message)
  
  flash('Disruption marked as resolved successfully!', 'success')
  return redirect(url_for('security_dashboard'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
  # Get counts for dashboard stats
  total_users = User.query.count()
  total_disruptions = Disruption.query.count()
  pending_disruptions = Disruption.query.filter_by(status='pending').count()
  resolved_disruptions = Disruption.query.filter_by(status='resolved').count()
  
  # Get recent users
  recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
  
  # Get recent disruptions
  recent_disruptions = Disruption.query.order_by(Disruption.created_at.desc()).limit(5).all()
  
  return render_template('admin_dashboard.html',
                        total_users=total_users,
                        total_disruptions=total_disruptions,
                        pending_disruptions=pending_disruptions,
                        resolved_disruptions=resolved_disruptions,
                        recent_users=recent_users,
                        recent_disruptions=recent_disruptions)

@app.route('/admin/users')
@admin_required
def admin_users():
  users = User.query.all()
  return render_template('admin_users.html', users=users)

@app.route('/admin/create-security-user', methods=['GET', 'POST'])
@admin_required
def create_security_user():
  security_teams = SecurityTeam.query.all()
  
  if request.method == 'POST':
      username = request.form.get('username')
      email = request.form.get('email')
      password = request.form.get('password')
      first_name = request.form.get('first_name')
      last_name = request.form.get('last_name')
      date_of_birth = request.form.get('date_of_birth')
      contact_number = request.form.get('contact_number')
      team_ids = request.form.getlist('team_ids')
      
      # Check if email already exists
      existing_user = User.query.filter_by(email=email).first()
      if existing_user:
          flash('Email already registered', 'danger')
          return redirect(url_for('create_security_user'))
      
      # Check if username already exists
      existing_username = User.query.filter_by(username=username).first()
      if existing_username:
          flash('Username already taken', 'danger')
          return redirect(url_for('create_security_user'))
      
      # Process profile picture if uploaded
      profile_picture = 'default_profile.png'
      if 'profile_picture' in request.files:
          file = request.files['profile_picture']
          if file.filename != '':
              saved_file = save_file(file, 'profiles')
              if saved_file:
                  profile_picture = saved_file
      
      # Create new security user
      hashed_password = generate_password_hash(password)
      
      # Convert date string to date object
      dob = None
      if date_of_birth:
          try:
              dob = datetime.strptime(date_of_birth, '%Y-%m-%d').date()
          except ValueError:
              flash('Invalid date format', 'danger')
              return redirect(url_for('create_security_user'))
      
      new_user = User(
          username=username,
          email=email,
          password=hashed_password,
          first_name=first_name,
          last_name=last_name,
          date_of_birth=dob,
          contact_number=contact_number,
          profile_picture=profile_picture,
          role='security'
      )
      
      db.session.add(new_user)
      db.session.commit()
      
      # Assign user to selected security teams
      for team_id in team_ids:
          team_member = SecurityTeamMember(
              user_id=new_user.id,
              team_id=team_id
          )
          db.session.add(team_member)
      
      db.session.commit()
      
      # Send welcome email to new security user
      subject = "Welcome to UniSafe Security Team"
      message = f"""
      Dear {first_name},
      
      Welcome to the UniSafe Security Team! Your account has been created successfully.
      
      Your login credentials:
      Email: {email}
      Password: {password}
      
      Please login at: {request.host_url}login
      
      Regards,
      UniSafe Admin Team
      """
      send_email_notification(email, subject, message)
      
      flash('Security user created successfully!', 'success')
      return redirect(url_for('admin_users'))
  
  return render_template('create_security_user.html', security_teams=security_teams)

@app.route('/admin/security-teams')
@admin_required
def admin_security_teams():
  security_teams = SecurityTeam.query.all()
  return render_template('admin_security_teams.html', security_teams=security_teams)

@app.route('/admin/view-team/<int:team_id>')
@admin_required
def view_team(team_id):
  team = SecurityTeam.query.get_or_404(team_id)
  team_members = SecurityTeamMember.query.filter_by(team_id=team_id).all()
  
  return render_template('view_team.html', team=team, team_members=team_members)

# Create database tables and initial data
with app.app_context():
  db.create_all()
  
  # Create campuses if they don't exist
  campuses = ['Steve Biko', 'Ritson', 'ML Sultan']
  for campus_name in campuses:
      if not Campus.query.filter_by(name=campus_name).first():
          campus = Campus(name=campus_name)
          db.session.add(campus)
  
  db.session.commit()
  
  # Create security teams for each campus if they don't exist
  for campus in Campus.query.all():
      for severity in ['low', 'medium', 'high']:
          if not SecurityTeam.query.filter_by(campus_id=campus.id, severity_level=severity).first():
              team = SecurityTeam(campus_id=campus.id, severity_level=severity)
              db.session.add(team)
  
  db.session.commit()
  
  # Create admin users if they don't exist
  admin_users = [
      {
          'email': 'admin@unisafe.ac.za',
          'username': 'Admin',
          'first_name': 'Admin',
          'last_name': 'User'
      },
      {
          'email': 'admin@dut.ac.za',
          'username': 'DUTAdmin',
          'first_name': 'DUT',
          'last_name': 'Admin'
      }
  ]
  
  for admin_data in admin_users:
      admin = User.query.filter_by(email=admin_data['email']).first()
      if not admin:
          admin_password = generate_password_hash('admin123')
          admin = User(
              username=admin_data['username'],
              email=admin_data['email'],
              password=admin_password,
              first_name=admin_data['first_name'],
              last_name=admin_data['last_name'],
              role='admin'
          )
          db.session.add(admin)
  
  db.session.commit()

if __name__ == '__main__':
  app.run(debug=True)


from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from PIL import Image
import os
from datetime import datetime, date
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-me')

# Fix DATABASE_URL for psycopg compatibility
database_url = os.environ.get('DATABASE_URL', 'sqlite:///app.db')
if database_url.startswith('postgresql://'):
    # Convert postgresql:// to postgresql+psycopg:// for modern psycopg driver
    database_url = database_url.replace('postgresql://', 'postgresql+psycopg://')

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Upload configuration
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_MIME_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}
# Limit decompression bomb risk
Image.MAX_IMAGE_PIXELS = 10_000_000

# Security/cookie settings for production
is_production = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('ENV') == 'production'
if is_production:
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        REMEMBER_COOKIE_SECURE=True,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE='Lax',
    )

# Initialize CSRF protection and expose helper to templates
csrf = CSRFProtect(app)
app.jinja_env.globals['csrf_token'] = generate_csrf

# Rate limiting
limiter = Limiter(key_func=get_remote_address, storage_uri=os.environ.get('RATELIMIT_STORAGE_URI', 'memory://'))
limiter.init_app(app)

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Association tables
membership = db.Table(
    'membership',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('project_id', db.Integer, db.ForeignKey('project.id'))
)

workspace_membership = db.Table(
    'workspace_membership',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('workspace_id', db.Integer, db.ForeignKey('workspace.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    full_name = db.Column(db.String(100), nullable=True)
    profile_picture = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    theme_preference = db.Column(db.String(10), default='light')
    task_view = db.Column(db.String(20), default='cards')
    notifications = db.Column(db.String(20), default='all')
    default_filter = db.Column(db.String(20), default='all')
    show_completed = db.Column(db.Boolean, default=True)
    enable_sounds = db.Column(db.Boolean, default=True)
    
    # Relationships
    owned_workspaces = db.relationship('Workspace', backref='owner', lazy=True)
    workspaces = db.relationship('Workspace', secondary=workspace_membership, back_populates='members')
    owned_projects = db.relationship('Project', backref='owner', lazy=True)
    projects = db.relationship('Project', secondary=membership, back_populates='members')
    assigned_tasks = db.relationship('Task', foreign_keys='Task.assignee_id', backref='assignee', lazy=True)
    created_tasks = db.relationship('Task', foreign_keys='Task.created_by', backref='creator', lazy=True)
    focus_sessions = db.relationship('FocusSession', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def has_workspace_access(self, workspace_id):
        workspace = Workspace.query.get(workspace_id)
        return workspace and (workspace.owner_id == self.id or workspace in self.workspaces)
    
    def get_role_in_project(self, project_id):
        project = Project.query.get(project_id)
        if not project:
            return None
        if project.owner_id == self.id:
            return 'owner'
        member_role = ProjectMember.query.filter_by(user_id=self.id, project_id=project_id).first()
        return member_role.role if member_role else None

class Workspace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    members = db.relationship('User', secondary=workspace_membership, back_populates='workspaces')
    projects = db.relationship('Project', backref='workspace', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, nullable=True)
    color = db.Column(db.String(7), default='#3b82f6')  # Hex color for project
    workspace_id = db.Column(db.Integer, db.ForeignKey('workspace.id'), nullable=True)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    members = db.relationship('User', secondary=membership, back_populates='projects')
    tasks = db.relationship('Task', backref='project', lazy=True)
    project_members = db.relationship('ProjectMember', backref='project', lazy=True)

class ProjectMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    role = db.Column(db.String(20), default='member')  # owner, admin, member, viewer
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    due = db.Column(db.Date)
    priority = db.Column(db.String(10), default='medium')
    status = db.Column(db.String(20), default='todo')  # todo, in_progress, review, completed
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    subtasks = db.relationship('Subtask', backref='parent', lazy=True)
    time_logs = db.relationship('TimeLog', backref='task', lazy=True)

class Subtask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'))
    title = db.Column(db.String(200), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class FocusSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=True)
    duration_minutes = db.Column(db.Integer, nullable=False)  # Planned duration
    actual_duration = db.Column(db.Integer, nullable=True)  # Actual time spent
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    session_type = db.Column(db.String(20), default='pomodoro')  # pomodoro, deep_work, break
    notes = db.Column(db.Text, nullable=True)

class TimeLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_id = db.Column(db.Integer, db.ForeignKey('task.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    duration_minutes = db.Column(db.Integer, nullable=False)
    date = db.Column(db.Date, default=date.today)
    description = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Example auth routes (register/login) to be implemented

@app.route("/login", methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid email or password')
    return render_template('login.html')

@app.route("/register", methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm = request.form.get('confirm', '')
        
        # Validate passwords match
        if password != confirm:
            flash('Passwords do not match')
            return render_template('register.html')
            
        # Check if user already exists
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return render_template('register.html')
            
        try:
            user = User(email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))
        except Exception as e:
            flash('An error occurred during registration. Please try again.')
            db.session.rollback()
            return render_template('register.html')
    return render_template('register.html')

@app.route("/logout", methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # handle project selection
    project_id = request.args.get('project', type=int)
    if project_id:
        project = Project.query.get_or_404(project_id)
    else:
        project = current_user.projects[0] if current_user.projects else None

    filt = request.args.get("filter", "all")
    today = date.today()

    query = Task.query.filter_by(project_id=project_id) if project_id else Task.query.filter_by(project_id=None)
    tasks = []
    for t in query.filter_by(completed=False).all():
        if not t.due and filt!='all':
            continue
        if t.due:
            if filt=='today' and t.due!=today: continue
            if filt=='upcoming' and t.due<=today: continue
            if filt=='overdue' and t.due>=today: continue
        tasks.append(t)

    completed = Task.query.filter_by(completed=True, project_id=project_id).all() if project_id else []
    projects = current_user.projects
    return render_template("index.html", tasks=tasks, completed=completed, today=today,
                           current_filter=filt, projects=projects, current_project=project)

@app.route("/add", methods=["POST"])
@login_required
def add_task():
    project_id = request.form.get('project_id', type=int)
    project = Project.query.get(project_id) if project_id else None
    
    task = Task(
        title=request.form["task"],
        due=datetime.strptime(request.form["due"], "%Y-%m-%d").date() if request.form.get("due") else None,
        priority=request.form.get("priority", "medium"),
        project_id=project_id,
        created_by=current_user.id
    )
    db.session.add(task)
    db.session.commit()
    
    # Redirect back to project if we came from project page
    if project_id:
        return redirect(url_for("project_detail", project_id=project_id))
    return redirect(url_for("index"))

@app.route("/add-sub/<int:tid>", methods=["POST"])
@login_required
def add_subtask(tid):
    task = Task.query.get_or_404(tid)
    text = request.form["subtask"].strip()
    if text:
        subtask = Subtask(title=text, parent=task)
        db.session.add(subtask)
        db.session.commit()
    return redirect(url_for("index"))

@app.route("/complete/<int:tid>", methods=['POST'])
@login_required
def complete_task(tid):
    task = Task.query.get_or_404(tid)
    # Enforce basic authorization: creator or project member
    if task.project_id:
        role = current_user.get_role_in_project(task.project_id)
        if role is None:
            flash('You do not have permission for this task')
            return redirect(request.referrer or url_for("index"))
    elif task.created_by != current_user.id:
        flash('You do not have permission for this task')
        return redirect(request.referrer or url_for("index"))
    task.completed = True
    task.completed_at = datetime.utcnow()
    db.session.commit()
    return redirect(request.referrer or url_for("index"))

@app.route("/complete-sub/<int:tid>/<int:sid>", methods=['POST'])
@login_required
def complete_subtask(tid, sid):
    subtask = Subtask.query.get_or_404(sid)
    # Authorization based on parent task
    parent_task = Task.query.get_or_404(tid)
    if parent_task.project_id:
        role = current_user.get_role_in_project(parent_task.project_id)
        if role is None:
            flash('You do not have permission for this subtask')
            return redirect(request.referrer or url_for("index"))
    elif parent_task.created_by != current_user.id:
        flash('You do not have permission for this subtask')
        return redirect(request.referrer or url_for("index"))
    subtask.completed = True
    db.session.commit()
    return redirect(request.referrer or url_for("index"))

@app.route("/delete/<int:tid>", methods=['POST'])
@login_required
def delete_task(tid):
    task = Task.query.get_or_404(tid)
    if task.project_id:
        role = current_user.get_role_in_project(task.project_id)
        if role is None:
            flash('You do not have permission to delete this task')
            return redirect(request.referrer or url_for("index"))
    elif task.created_by != current_user.id:
        flash('You do not have permission to delete this task')
        return redirect(request.referrer or url_for("index"))
    db.session.delete(task)
    db.session.commit()
    return redirect(request.referrer or url_for("index"))

@app.route("/delete-sub/<int:tid>/<int:sid>", methods=['POST'])
@login_required
def delete_subtask(tid, sid):
    subtask = Subtask.query.get_or_404(sid)
    parent_task = Task.query.get_or_404(tid)
    if parent_task.project_id:
        role = current_user.get_role_in_project(parent_task.project_id)
        if role is None:
            flash('You do not have permission to delete this subtask')
            return redirect(request.referrer or url_for("index"))
    elif parent_task.created_by != current_user.id:
        flash('You do not have permission to delete this subtask')
        return redirect(request.referrer or url_for("index"))
    db.session.delete(subtask)
    db.session.commit()
    return redirect(request.referrer or url_for("index"))

@app.route("/reorder", methods=["POST"])
@limiter.limit("60 per minute")
@login_required
def reorder():
    # Note: This would need more complex implementation for SQLAlchemy
    return jsonify(success=True)

@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        profile_picture = request.files.get('profile_picture')
        
        try:
            # Update full name
            current_user.full_name = full_name if full_name else None
            
            # Update password if provided
            if new_password:
                if not current_password:
                    flash('Current password is required to change password')
                    return render_template('profile.html')
                if not current_user.check_password(current_password):
                    flash('Current password is incorrect')
                    return render_template('profile.html')
                if new_password != confirm_password:
                    flash('New passwords do not match')
                    return render_template('profile.html')
                current_user.set_password(new_password)
            
            # Handle profile picture upload
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    if allowed_file(file.filename) and (file.mimetype in ALLOWED_MIME_TYPES):
                        # Delete old profile picture
                        if current_user.profile_picture:
                            delete_profile_picture(current_user.profile_picture)
                        
                        # Save new profile picture
                        filename = save_profile_picture(file)
                        if filename:
                            current_user.profile_picture = filename
                    else:
                        flash('Invalid file type. Please upload PNG, JPG, JPEG, GIF, or WEBP images only.')
                        return render_template('profile.html')
            
            db.session.commit()
            flash('Profile updated successfully!')
            return redirect(url_for('profile'))
            
        except Exception as e:
            flash('An error occurred while updating your profile')
            db.session.rollback()
            return render_template('profile.html')
    
    return render_template('profile.html')

@app.route("/remove_profile_picture", methods=['POST'])
@login_required
def remove_profile_picture():
    try:
        if current_user.profile_picture:
            delete_profile_picture(current_user.profile_picture)
            current_user.profile_picture = None
            db.session.commit()
            flash('Profile picture removed successfully!')
        else:
            flash('No profile picture to remove')
    except Exception as e:
        flash('An error occurred while removing profile picture')
        db.session.rollback()
    
    return redirect(url_for('profile'))

@app.route("/settings", methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        theme = request.form.get('theme', 'light')
        task_view = request.form.get('task_view', 'cards')
        notifications = request.form.get('notifications', 'all')
        default_filter = request.form.get('default_filter', 'all')
        show_completed = 'show_completed' in request.form
        enable_sounds = 'enable_sounds' in request.form
        
        try:
            current_user.theme_preference = theme
            current_user.task_view = task_view
            current_user.notifications = notifications
            current_user.default_filter = default_filter
            current_user.show_completed = show_completed
            current_user.enable_sounds = enable_sounds
            db.session.commit()
            flash('Settings saved successfully!')
            return redirect(url_for('settings'))
        except Exception as e:
            flash('An error occurred while saving settings')
            db.session.rollback()
            return render_template('settings.html')
    
    return render_template('settings.html')

# Workspace Management Routes
@app.route("/workspaces")
@login_required
def workspaces():
    # Combine owned and member workspaces without duplicates
    owned = list(current_user.owned_workspaces)
    member = list(current_user.workspaces)
    seen = set()
    user_workspaces = []
    for w in owned + member:
        if w.id not in seen:
            seen.add(w.id)
            user_workspaces.append(w)
    return render_template('workspaces.html', workspaces=user_workspaces)

@app.route("/workspace/create", methods=['GET', 'POST'])
@login_required
def create_workspace():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        
        if not name:
            flash('Workspace name is required')
            return render_template('create_workspace.html')
        
        try:
            workspace = Workspace(
                name=name,
                description=description if description else None,
                owner_id=current_user.id
            )
            db.session.add(workspace)
            db.session.commit()
            flash('Workspace created successfully!')
            return redirect(url_for('workspace_detail', workspace_id=workspace.id))
        except Exception as e:
            flash('An error occurred while creating the workspace')
            db.session.rollback()
            return render_template('create_workspace.html')
    
    return render_template('create_workspace.html')

@app.route("/workspace/<int:workspace_id>")
@login_required
def workspace_detail(workspace_id):
    workspace = Workspace.query.get_or_404(workspace_id)
    
    # Check access
    if not current_user.has_workspace_access(workspace_id):
        flash('You do not have access to this workspace')
        return redirect(url_for('workspaces'))
    
    projects = workspace.projects
    return render_template('workspace_detail.html', workspace=workspace, projects=projects)

@app.route("/workspace/<int:workspace_id>/invite", methods=['POST'])
@login_required
def invite_to_workspace(workspace_id):
    # TODO: Implement workspace invitation system
    pass

@app.route("/workspace/<int:workspace_id>/delete", methods=['POST'])
@login_required
def delete_workspace(workspace_id):
    workspace = Workspace.query.get_or_404(workspace_id)
    
    # Only workspace owner can delete
    if workspace.owner_id != current_user.id:
        flash('You do not have permission to delete this workspace')
        return redirect(url_for('workspaces'))
    
    try:
        # Delete associated projects and their tasks
        for project in workspace.projects:
            # Delete tasks in each project
            Task.query.filter_by(project_id=project.id).delete()
            # Delete project members
            ProjectMember.query.filter_by(project_id=project.id).delete()
            # Delete the project
            db.session.delete(project)
        
        # Remove workspace memberships
        workspace.members.clear()
        
        # Delete the workspace
        db.session.delete(workspace)
        db.session.commit()
        
        flash('Workspace deleted successfully!')
    except Exception as e:
        flash('An error occurred while deleting the workspace')
        db.session.rollback()
    
    return redirect(url_for('workspaces'))

# Project Management Routes
@app.route("/project/create", methods=['GET', 'POST'])
@login_required
def create_project():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        description = request.form.get('description', '').strip()
        color = request.form.get('color', '#3b82f6')
        workspace_id = request.form.get('workspace_id', type=int)
        
        if not name:
            flash('Project name is required')
            return render_template('create_project.html')
        
        # Validate workspace access if specified
        if workspace_id and not current_user.has_workspace_access(workspace_id):
            flash('You do not have access to the selected workspace')
            return render_template('create_project.html')
        
        try:
            project = Project(
                name=name,
                description=description if description else None,
                color=color,
                workspace_id=workspace_id,
                owner_id=current_user.id
            )
            db.session.add(project)
            db.session.flush()  # Get the project ID
            
            # Add owner as project member with owner role
            project_member = ProjectMember(
                user_id=current_user.id,
                project_id=project.id,
                role='owner'
            )
            db.session.add(project_member)
            db.session.commit()
            
            flash('Project created successfully!')
            return redirect(url_for('project_detail', project_id=project.id))
        except Exception as e:
            flash('An error occurred while creating the project')
            db.session.rollback()
            return render_template('create_project.html')
    
    workspaces = current_user.owned_workspaces + list(current_user.workspaces)
    # Deduplicate workspaces for dropdown
    ws_seen = set()
    deduped_workspaces = []
    for w in workspaces:
        if w.id not in ws_seen:
            ws_seen.add(w.id)
            deduped_workspaces.append(w)
    return render_template('create_project.html', workspaces=deduped_workspaces)

@app.route("/project/<int:project_id>")
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check access
    user_role = current_user.get_role_in_project(project_id)
    if not user_role:
        flash('You do not have access to this project')
        return redirect(url_for('index'))
    
    tasks = Task.query.filter_by(project_id=project_id).all()
    return render_template('project_detail.html', project=project, tasks=tasks, user_role=user_role, today=date.today())

@app.route("/project/<int:project_id>/delete", methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Check if user has permission to delete (owner or admin)
    user_role = current_user.get_role_in_project(project_id)
    if user_role not in ['owner', 'admin']:
        flash('You do not have permission to delete this project')
        return redirect(url_for('project_detail', project_id=project_id))
    
    try:
        # Delete associated tasks and subtasks
        tasks = Task.query.filter_by(project_id=project_id).all()
        for task in tasks:
            # Delete subtasks
            Subtask.query.filter_by(task_id=task.id).delete()
            # Delete time logs
            TimeLog.query.filter_by(task_id=task.id).delete()
            # Delete the task
            db.session.delete(task)
        
        # Delete project members
        ProjectMember.query.filter_by(project_id=project_id).delete()
        
        # Clear project memberships
        project.members.clear()
        
        # Delete the project
        db.session.delete(project)
        db.session.commit()
        
        flash('Project deleted successfully!')
        
        # Redirect to workspace if project belonged to one, otherwise to dashboard
        if project.workspace_id:
            return redirect(url_for('workspace_detail', workspace_id=project.workspace_id))
        else:
            return redirect(url_for('index'))
            
    except Exception as e:
        flash('An error occurred while deleting the project')
        db.session.rollback()
        return redirect(url_for('project_detail', project_id=project_id))

@app.route("/projects")
@login_required
def all_projects():
    # Get all projects where user is owner or member
    owned_projects = Project.query.filter_by(owner_id=current_user.id).all()
    member_projects = []
    
    # Get projects where user is a member
    project_memberships = ProjectMember.query.filter_by(user_id=current_user.id).all()
    for membership in project_memberships:
        if membership.project.owner_id != current_user.id:  # Avoid duplicates
            member_projects.append(membership.project)
    
    all_user_projects = owned_projects + member_projects
    
    return render_template('all_projects.html', 
                         owned_projects=owned_projects,
                         member_projects=member_projects,
                         all_projects=all_user_projects)

# Focus Timer Routes
@app.route("/focus")
@login_required
def focus_timer():
    recent_sessions = FocusSession.query.filter_by(user_id=current_user.id)\
                                      .order_by(FocusSession.started_at.desc())\
                                      .limit(10).all()
    return render_template('focus_timer.html', recent_sessions=recent_sessions)

@app.route("/focus/start", methods=['POST'])
@limiter.limit("30 per minute")
@login_required
def start_focus_session():
    duration = request.form.get('duration', 25, type=int)
    task_id = request.form.get('task_id', type=int)
    session_type = request.form.get('session_type', 'pomodoro')
    
    try:
        session = FocusSession(
            user_id=current_user.id,
            task_id=task_id,
            duration_minutes=duration,
            session_type=session_type
        )
        db.session.add(session)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'session_id': session.id,
            'duration': duration
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route("/focus/complete", methods=['POST'])
@limiter.limit("30 per minute")
@login_required
def complete_focus_session():
    session_id = request.form.get('session_id', type=int)
    actual_duration = request.form.get('actual_duration', type=int)
    notes = request.form.get('notes', '').strip()
    
    session = FocusSession.query.get_or_404(session_id)
    
    if session.user_id != current_user.id:
        return jsonify({'success': False, 'error': 'Unauthorized'})
    
    try:
        session.actual_duration = actual_duration
        session.notes = notes if notes else None
        session.completed_at = datetime.utcnow()
        
        # Log time to task if associated
        if session.task_id and actual_duration > 0:
            time_log = TimeLog(
                task_id=session.task_id,
                user_id=current_user.id,
                duration_minutes=actual_duration,
                description=f"Focus session: {session.session_type}"
            )
            db.session.add(time_log)
        
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def save_profile_picture(file):
    if file and allowed_file(file.filename) and (file.mimetype in ALLOWED_MIME_TYPES):
        try:
            # Verify and sanitize image
            file.stream.seek(0)
            img = Image.open(file.stream)
            img.verify()  # Basic integrity check
            file.stream.seek(0)
            img = Image.open(file.stream)
            # Normalize mode
            if img.mode not in ("RGB", "RGBA"):
                img = img.convert("RGB")
            # Resize to a sane maximum
            max_size = (1024, 1024)
            img.thumbnail(max_size)

            # Generate unique filename and choose format based on extension
            filename = secure_filename(file.filename)
            name, ext = os.path.splitext(filename)
            ext = ext.lower()
            if ext not in ['.png', '.jpg', '.jpeg', '.gif', '.webp']:
                ext = '.png'
            fmt = 'PNG'
            save_kwargs = {}
            if ext in ['.jpg', '.jpeg']:
                fmt = 'JPEG'
                if img.mode == 'RGBA':
                    img = img.convert('RGB')
                save_kwargs.update({'quality': 85, 'optimize': True})
            elif ext == '.gif':
                fmt = 'GIF'
            elif ext == '.webp':
                fmt = 'WEBP'
                save_kwargs.update({'quality': 80})

            unique_filename = f"{uuid.uuid4().hex}{ext}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            img.save(file_path, format=fmt, **save_kwargs)
            return unique_filename
        except Exception:
            return None
    return None

def delete_profile_picture(filename):
    if filename:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception:
            pass  # Silently fail if file can't be deleted

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    # Return JSON for API/fetch requests
    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest' or (request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html):
        return jsonify({'success': False, 'error': 'CSRF token missing or invalid'}), 400
    flash('Security check failed. Please refresh the page and try again.')
    return redirect(request.referrer or url_for('index'))

# Health check endpoint for monitoring
@app.route('/health')
def health_check():
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503

@app.after_request
def add_security_headers(response):
    # Basic hardening headers (keep CSP minimal to avoid blocking external CDNs)
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    # Additional headers for production
    if is_production:
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload')
        response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
        response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
        response.headers.setdefault('Cross-Origin-Resource-Policy', 'same-origin')
    return response

# For Vercel deployment
if __name__ == "__main__":
    app.run(debug=True, port=5004)

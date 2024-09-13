from flask import Flask, render_template, url_for, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt

app = Flask(__name__)

# Configurar banco de dados
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = '039@PwPM2Y#VdkI0X%J0WeYR#JS6e'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
from Flfpfkla´ps
# login_manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# hashear as senhas
bcrypt = Bcrypt(app)

# Criar tabela de usuário
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# validação de registro
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Usuário"})
    
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Senha"})
    
    submit = SubmitField("Registrar")
    
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()

        if existing_user_username:
            raise ValidationError("Esse usuário já existe. Por favor, escolha um diferente")


# validação de login
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Usuário"})
    
    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=20)], render_kw={"placeholder": "Senha"})
    
    submit = SubmitField("Entrar")


# Rota de página principal
@app.route('/')
def home():
    return render_template('index.html')


# Rota de página de login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha incorretos', 'error')
    return render_template('login.html', form=form)


# Rota para dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


# Rota de página de registro
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)


# Rota de logout
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# Criar as tabelas dentro de um contexto de aplicação
with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run(debug=True)

# Se o projeto crescer,
# é uma boa prática separar as partes do código em diferentes módulos e pastas 
# (routes.py, models.py, forms.py etc.).

# Depois de verificar a senha, considere remover a senha em texto claro da memória, mesmo que seja descartada logo em seguida. 
# Isso é uma boa prática de segurança.

# No registro, se ocorrer um erro durante a criação do usuário (por exemplo, problema no banco de dados),
# o usuário não receberá feedback.
# sugestão: Utilize um bloco try-except ao redor do código de criação do usuário para capturar e exibir erros.



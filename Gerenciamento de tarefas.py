from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_cors import CORS
from utils.models import User, Task
from datetime import timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app)

# Rotas de autenticação
@app.route('/register', methods=['POST'])
def register():
    email = request.json.get('email')
    password = request.json.get('password')

    if not email or not password:
        return jsonify({'message': 'Email se senha sao necessarios'}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Email ja registrado'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    new_user = User(email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Usuario registrado com sucesso'}), 201

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Email ou senha invalidos'}), 401

    access_token = create_access_token(identity=user.id)

    return jsonify({'access_token': access_token}), 200

# Rotas de tarefas
@app.route('/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    user_id = request.jwt_identity
    tasks = Task.query.filter_by(user_id=user_id).all()
    task_list = []

    for task in tasks:
        task_list.append({'id': task.id, 'title': task.title, 'description': task.description})

    return jsonify({'tasks': task_list}), 200

@app.route('/tasks', methods=['POST'])
@jwt_required()
def create_task():
    user_id = request.jwt_identity
    title = request.json.get('title')
    description = request.json.get('description')

    if not title or not description:
        return jsonify({'message': 'Titulo e descricao sao obrigatorios'}), 400

    new_task = Task(title=title, description=description, user_id=user_id)
    db.session.add(new_task)
    db.session.commit()

    return jsonify({'message': 'Tarefa criada com successo'}), 201

@app.route('/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    user_id = request.jwt_identity
    task = Task.query.filter_by(id=task_id, user_id=user_id).first()

    if not task:
        return jsonify({'message': 'Tarefa nao encocntrada'}), 404

    task.title = request.json.get('title', task.title)
    task.description = request.json.get('description', task.description)

    db.session.commit()

    return jsonify({'message': 'Tarefa atualizada com sucesso'}), 200

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    user_id = request.jwt_identity
    task = Task.query.filter_by(id=task_id, user_id=user_id).first()

    if not task:
        return jsonify({'message': 'Tarefa nao encontrada'}), 404

    db.session.delete(task)
    db.session.commit()

    return jsonify({'message': 'Tarefa deletada com sucesso'}), 200

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
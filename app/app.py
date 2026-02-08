from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import os
import uuid
from datetime import datetime
import re
import threading
import time
import json
from collections import defaultdict

app = Flask(__name__, static_folder='dist', static_url_path='')
CORS(app)

# Конфигурация
app.config['SECRET_KEY'] = 'distint-competition-2026-secret-key'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-2026'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False
jwt = JWTManager(app)

# Простой WebSocket эмулятор
websocket_clients = defaultdict(list)
board_subscriptions = defaultdict(set)

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Пользователи
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Доски
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS boards (
        id TEXT PRIMARY KEY,
        hash TEXT UNIQUE NOT NULL,
        title TEXT NOT NULL,
        owner_id TEXT NOT NULL,
        owner_name TEXT NOT NULL,
        is_public BOOLEAN DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (owner_id) REFERENCES users(id)
    )
    ''')
    
    # Объекты на досках
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS board_objects (
        id TEXT PRIMARY KEY,
        board_id TEXT NOT NULL,
        type TEXT NOT NULL,
        content TEXT,
        x INTEGER NOT NULL,
        y INTEGER NOT NULL,
        width INTEGER NOT NULL,
        height INTEGER NOT NULL,
        color TEXT,
        font_size INTEGER,
        locked_by TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (board_id) REFERENCES boards(id)
    )
    ''')
    
    # Лайки
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS board_likes (
        id TEXT PRIMARY KEY,
        board_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(board_id, user_id),
        FOREIGN KEY (board_id) REFERENCES boards(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    # Общий доступ к доскам
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS board_shares (
        id TEXT PRIMARY KEY,
        board_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        can_edit BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(board_id, user_id),
        FOREIGN KEY (board_id) REFERENCES boards(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')
    
    conn.commit()
    conn.close()

# Утилиты для работы с БД
def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def generate_id():
    return str(uuid.uuid4())[:8]

# Валидация
def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_name(name):
    return bool(re.match(r'^[a-zA-Z\s]+$', name))

def validate_password(password):
    if len(password) < 8:
        return False, "Минимум 8 символов"
    if not any(c.isdigit() for c in password):
        return False, "Нужна хотя бы одна цифра"
    if not any(c in "!@#$%^&*" for c in password):
        return False, "Нужен спецсимвол !@#$%^&*"
    return True, ""

# API: Регистрация
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data.get('email') or not data.get('name') or not data.get('password'):
        return jsonify({"message": "Все поля обязательны"}), 400
    
    if not validate_email(data['email']):
        return jsonify({"message": "Неверный формат email"}), 400
    
    is_valid, msg = validate_password(data['password'])
    if not is_valid:
        return jsonify({"message": msg}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Проверка существования пользователя
    cursor.execute("SELECT id FROM users WHERE email = ?", (data['email'],))
    if cursor.fetchone():
        conn.close()
        return jsonify({"message": "Пользователь уже существует"}), 400
    
    # Создание пользователя
    user_id = generate_id()
    cursor.execute(
        "INSERT INTO users (id, email, name, password) VALUES (?, ?, ?, ?)",
        (user_id, data['email'], data['name'], data['password'])
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "message": "Регистрация успешна",
        "user": {
            "id": user_id,
            "email": data['email'],
            "name": data['name']
        }
    }), 201

# API: Авторизация
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data.get('email') or not data.get('password'):
        return jsonify({"message": "Email и пароль обязательны"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id, email, name, password FROM users WHERE email = ?", (data['email'],))
    user = cursor.fetchone()
    conn.close()
    
    if not user or user['password'] != data['password']:
        return jsonify({"message": "Неверный email или пароль"}), 401
    
    access_token = create_access_token(identity=user['id'])
    
    return jsonify({
        "access_token": access_token,
        "user": {
            "id": user['id'],
            "email": user['email'],
            "name": user['name']
        }
    })

# API: Мои доски
@app.route('/api/boards/my', methods=['GET'])
@jwt_required()
def my_boards():
    user_id = get_jwt_identity()
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT b.*, 
               (SELECT COUNT(*) FROM board_likes WHERE board_id = b.id) as likes,
               (SELECT COUNT(*) > 0 FROM board_likes WHERE board_id = b.id AND user_id = ?) as liked_by_me
        FROM boards b
        WHERE b.owner_id = ?
        ORDER BY b.created_at DESC
    ''', (user_id, user_id))
    
    boards = []
    for row in cursor.fetchall():
        board = dict(row)
        board['can_edit'] = True
        boards.append(board)
    
    conn.close()
    return jsonify({"boards": boards})

# API: Публичные доски
@app.route('/api/boards/public', methods=['GET'])
def public_boards():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT b.*, 
               (SELECT COUNT(*) FROM board_likes WHERE board_id = b.id) as likes,
               0 as liked_by_me,
               0 as can_edit
        FROM boards b
        WHERE b.is_public = 1
        ORDER BY likes DESC, b.created_at DESC
    ''')
    
    boards = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({"boards": boards})

# API: Общие доски
@app.route('/api/boards/shared', methods=['GET'])
@jwt_required()
def shared_boards():
    user_id = get_jwt_identity()
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT b.*, 
               (SELECT COUNT(*) FROM board_likes WHERE board_id = b.id) as likes,
               (SELECT COUNT(*) > 0 FROM board_likes WHERE board_id = b.id AND user_id = ?) as liked_by_me,
               bs.can_edit
        FROM boards b
        JOIN board_shares bs ON b.id = bs.board_id
        WHERE bs.user_id = ? AND b.owner_id != ?
        ORDER BY b.created_at DESC
    ''', (user_id, user_id, user_id))
    
    boards = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({"boards": boards})

# API: Создать доску
@app.route('/api/boards', methods=['POST'])
@jwt_required()
def create_board():
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data.get('title'):
        return jsonify({"message": "Название обязательно"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({"message": "Пользователь не найден"}), 404
    
    board_id = generate_id()
    board_hash = generate_id()
    
    cursor.execute(
        '''INSERT INTO boards (id, hash, title, owner_id, owner_name, is_public) 
           VALUES (?, ?, ?, ?, ?, ?)''',
        (board_id, board_hash, data['title'], user_id, user['name'], data.get('is_public', False))
    )
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "id": board_id,
        "hash": board_hash,
        "title": data['title'],
        "owner_id": user_id,
        "owner_name": user['name'],
        "is_public": data.get('is_public', False)
    }), 201

# API: Получить доску
@app.route('/api/boards/<board_id>', methods=['GET'])
def get_board(board_id):
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT b.*, 
               (SELECT COUNT(*) FROM board_likes WHERE board_id = b.id) as likes
        FROM boards b
        WHERE b.id = ? OR b.hash = ?
    ''', (board_id, board_id))
    
    board = cursor.fetchone()
    if not board:
        conn.close()
        return jsonify({"message": "Доска не найдена"}), 404
    
    board = dict(board)
    
    auth_header = request.headers.get('Authorization')
    has_access = board['is_public'] == 1
    
    if auth_header and auth_header.startswith('Bearer '):
        try:
            cursor.execute("SELECT id FROM users WHERE id = ?", (board['owner_id'],))
            user = cursor.fetchone()
            
            if user:
                user_id = user['id']
                if board['owner_id'] == user_id:
                    has_access = True
                    board['can_edit'] = True
                else:
                    cursor.execute(
                        "SELECT can_edit FROM board_shares WHERE board_id = ? AND user_id = ?",
                        (board['id'], user_id)
                    )
                    share = cursor.fetchone()
                    if share:
                        has_access = True
                        board['can_edit'] = share['can_edit'] == 1
        except:
            pass
    
    if not has_access:
        conn.close()
        return jsonify({"message": "Нет доступа"}), 403
    
    cursor.execute("SELECT * FROM board_objects WHERE board_id = ?", (board['id'],))
    board['objects'] = [dict(obj) for obj in cursor.fetchall()]
    
    if auth_header and auth_header.startswith('Bearer '):
        try:
            cursor.execute(
                "SELECT 1 FROM board_likes WHERE board_id = ? AND user_id = ?",
                (board['id'], board['owner_id'])
            )
            board['liked_by_me'] = cursor.fetchone() is not None
        except:
            board['liked_by_me'] = False
    else:
        board['liked_by_me'] = False
    
    conn.close()
    return jsonify(board)

# API: Сохранить объекты доски
@app.route('/api/boards/<board_id>/objects', methods=['POST'])
@jwt_required()
def save_objects(board_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data.get('objects'):
        return jsonify({"message": "Нет объектов для сохранения"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT owner_id FROM boards WHERE id = ?", (board_id,))
    board = cursor.fetchone()
    
    if not board:
        conn.close()
        return jsonify({"message": "Доска не найдена"}), 404
    
    if board['owner_id'] != user_id:
        cursor.execute(
            "SELECT can_edit FROM board_shares WHERE board_id = ? AND user_id = ? AND can_edit = 1",
            (board_id, user_id)
        )
        if not cursor.fetchone():
            conn.close()
            return jsonify({"message": "Нет прав на редактирование"}), 403
    
    cursor.execute("DELETE FROM board_objects WHERE board_id = ?", (board_id,))
    
    for obj in data['objects']:
        obj_id = obj.get('id') or generate_id()
        cursor.execute('''
            INSERT INTO board_objects (id, board_id, type, content, x, y, width, height, color, font_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            obj_id, board_id, obj['type'], obj.get('content'), 
            obj['x'], obj['y'], obj['width'], obj['height'],
            obj.get('color'), obj.get('fontSize')
        ))
    
    conn.commit()
    conn.close()

    broadcast_to_board(board_id, {
        'type': 'objects_saved',
        'board_id': board_id,
        'user_id': user_id,
        'timestamp': datetime.now().isoformat()
    })
    
    return jsonify({"message": "Объекты сохранены"})

@app.route('/api/boards/<board_id>/objects/update', methods=['POST'])
@jwt_required()
def update_object(board_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT owner_id FROM boards WHERE id = ?", (board_id,))
    board = cursor.fetchone()
    
    if not board:
        conn.close()
        return jsonify({"message": "Доска не найдена"}), 404
    
    if board['owner_id'] != user_id:
        cursor.execute(
            "SELECT can_edit FROM board_shares WHERE board_id = ? AND user_id = ? AND can_edit = 1",
            (board_id, user_id)
        )
        if not cursor.fetchone():
            conn.close()
            return jsonify({"message": "Нет прав на редактирование"}), 403
    
    obj_data = data.get('object')
    if not obj_data:
        conn.close()
        return jsonify({"message": "Нет данных объекта"}), 400
    
    # Сохраняем объект в БД
    obj_id = obj_data.get('id') or generate_id()
    
    cursor.execute('''
        INSERT OR REPLACE INTO board_objects 
        (id, board_id, type, content, x, y, width, height, color, font_size)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        obj_id, board_id, obj_data['type'], obj_data.get('content'), 
        obj_data['x'], obj_data['y'], obj_data['width'], obj_data['height'],
        obj_data.get('color'), obj_data.get('fontSize')
    ))
    
    conn.commit()
    
    # Получаем информацию о пользователе
    cursor.execute("SELECT name FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    user_name = user['name'] if user else 'Неизвестно'
    
    conn.close()

    broadcast_to_board(board_id, {
        'type': 'object_updated',
        'board_id': board_id,
        'object': obj_data,
        'user_id': user_id,
        'user_name': user_name,
        'timestamp': datetime.now().isoformat()
    })
    
    return jsonify({"message": "Объект обновлен", "object_id": obj_id})

# API: Лайк доски
@app.route('/api/boards/<board_id>/like', methods=['POST'])
@jwt_required()
def like_board(board_id):
    user_id = get_jwt_identity()
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM boards WHERE id = ?", (board_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"message": "Доска не найдена"}), 404
    
    cursor.execute(
        "SELECT id FROM board_likes WHERE board_id = ? AND user_id = ?",
        (board_id, user_id)
    )
    
    if cursor.fetchone():
        cursor.execute(
            "DELETE FROM board_likes WHERE board_id = ? AND user_id = ?",
            (board_id, user_id)
        )
        liked = False
    else:
        like_id = generate_id()
        cursor.execute(
            "INSERT INTO board_likes (id, board_id, user_id) VALUES (?, ?, ?)",
            (like_id, board_id, user_id)
        )
        liked = True
    
    cursor.execute("SELECT COUNT(*) as count FROM board_likes WHERE board_id = ?", (board_id,))
    likes_count = cursor.fetchone()['count']
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "liked": liked,
        "likes_count": likes_count
    })

# API: Поделиться доской
@app.route('/api/boards/<board_id>/share', methods=['POST'])
@jwt_required()
def share_board(board_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data.get('email'):
        return jsonify({"message": "Email обязателен"}), 400
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT owner_id FROM boards WHERE id = ?", (board_id,))
    board = cursor.fetchone()
    
    if not board:
        conn.close()
        return jsonify({"message": "Доска не найдена"}), 404
    
    if board['owner_id'] != user_id:
        conn.close()
        return jsonify({"message": "Только владелец может делиться доской"}), 403
    
    cursor.execute("SELECT id FROM users WHERE email = ?", (data['email'],))
    user_to_share = cursor.fetchone()
    
    if not user_to_share:
        conn.close()
        return jsonify({"message": "Пользователь не найден"}), 404
    
    if user_to_share['id'] == user_id:
        conn.close()
        return jsonify({"message": "Нельзя поделиться с самим собой"}), 400
    
    share_id = generate_id()
    try:
        cursor.execute(
            "INSERT INTO board_shares (id, board_id, user_id) VALUES (?, ?, ?)",
            (share_id, board_id, user_to_share['id'])
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Доска успешно расшарена"})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"message": "Доступ уже предоставлен"}), 400

# WebSocket эмуляция через long polling
@app.route('/api/ws/subscribe/<board_id>', methods=['GET'])
@jwt_required()
def ws_subscribe(board_id):
    user_id = get_jwt_identity()
    

    client_id = generate_id()

    if board_id not in board_subscriptions:
        board_subscriptions[board_id] = set()
    
    board_subscriptions[board_id].add(client_id)
    

    return jsonify({
        'client_id': client_id,
        'board_id': board_id,
        'message': 'Подписка оформлена'
    })

@app.route('/api/ws/poll/<client_id>', methods=['GET'])
@jwt_required()
def ws_poll(client_id):

    user_id = get_jwt_identity()
    

    board_id = None
    for bid, clients in board_subscriptions.items():
        if client_id in clients:
            board_id = bid
            break
    
    if not board_id:
        return jsonify({"message": "Клиент не найден"}), 404
    return jsonify({
        'type': 'heartbeat',
        'timestamp': datetime.now().isoformat(),
        'board_id': board_id,
        'message': 'Соединение активно'
    })

# Функция для рассылки сообщений подписчикам доски
def broadcast_to_board(board_id, message):
    print(f"Broadcast to board {board_id}: {message}")



@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('dist', path)

# Создаем тестового пользователя
def create_test_user():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT id FROM users WHERE email = ?", ('test@test.com',))
    if not cursor.fetchone():
        test_id = generate_id()
        cursor.execute(
            "INSERT INTO users (id, email, name, password) VALUES (?, ?, ?, ?)",
            (test_id, 'test@test.com', 'Тестовый пользователь', 'Test123!')
        )
        
        board_id = generate_id()
        cursor.execute(
            '''INSERT INTO boards (id, hash, title, owner_id, owner_name, is_public) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (board_id, 'test123', 'Пример публичной доски', test_id, 'Тестовый пользователь', 1)
        )
        
        cursor.execute(
            '''INSERT INTO board_objects (id, board_id, type, content, x, y, width, height, color, font_size)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            ('obj1', board_id, 'text', 'Добро пожаловать в DiStInt!', 100, 100, 300, 50, '#333333', 24)
        )
        
        cursor.execute(
            '''INSERT INTO board_objects (id, board_id, type, content, x, y, width, height, color)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            ('obj2', board_id, 'rectangle', None, 300, 200, 150, 100, '#4287f5')
        )
        
        cursor.execute(
            '''INSERT INTO board_objects (id, board_id, type, content, x, y, width, height, color)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            ('obj3', board_id, 'circle', None, 500, 150, 100, 100, '#42f554')
        )
        
        conn.commit()
        print("=" * 60)
        print("Создан тестовый пользователь:")
        print("Email: test@test.com")
        print("Пароль: Test123!")
        print("=" * 60)
    
    conn.close()

if __name__ == '__main__':
    init_db()
    create_test_user()
    app.run(debug=True, host='0.0.0.0', port=5000)
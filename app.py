from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, make_response, session, send_from_directory, current_app
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import sqlite3
import time
import os
from datetime import datetime
import pytz
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import generate_csrf
from flask_socketio import SocketIO
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask import current_app
from werkzeug.exceptions import BadRequest

# ----------- CONFIGURACIÓN INICIAL -----------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Zona horaria Perú y helper para obtener timestamp local
PE_TZ = pytz.timezone('America/Lima')
def now_peru():
    return datetime.now(PE_TZ)

def get_year_month(dt=None):
    if dt is None:
        dt = now_peru()
    return dt.strftime('%Y-%m')

def get_trader_stats(trader_id, year_month):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("""
        SELECT utilidad_dia, utilidad_mes, meta_mes
        FROM trader_stats
        WHERE trader_id = ? AND year_month = ?
    """, (trader_id, year_month))
    row = c.fetchone()
    conn.close()
    if row:
        return {'utilidad_dia': row[0], 'utilidad_mes': row[1], 'meta_mes': row[2]}
    else:
        return {'utilidad_dia': 0, 'utilidad_mes': 0, 'meta_mes': 0}

def set_trader_stats(trader_id, year_month, utilidad_dia=None, utilidad_mes=None, meta_mes=None):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    
    # Inserta registro si no existe (para asegurar que la fila exista antes de actualizar)
    c.execute("""
        INSERT OR IGNORE INTO trader_stats (trader_id, year_month, utilidad_dia, utilidad_mes, meta_mes)
        VALUES (?, ?, 0, 0, 0)
    """, (trader_id, year_month))
    
    # Construir update solo con los campos proporcionados
    updates = []
    params = []
    
    if utilidad_dia is not None:
        updates.append("utilidad_dia = ?")
        params.append(utilidad_dia)
    
    if utilidad_mes is not None:
        updates.append("utilidad_mes = ?")
        params.append(utilidad_mes)
    
    if meta_mes is not None:
        updates.append("meta_mes = ?")
        params.append(meta_mes)
    
    if updates:
        query = f"UPDATE trader_stats SET {', '.join(updates)} WHERE trader_id = ? AND year_month = ?"
        params.extend([trader_id, year_month])
        c.execute(query, params)
    
    conn.commit()
    conn.close()

MAX_FILE_SIZE_MB = 5

def allowed_file(filename):
    allowed_extensions = {'png', 'jpg', 'jpeg', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

def crear_usuario(db_path, username, password, role, dni, email, status="Activo"):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    password_hash = generate_password_hash(password)
    # Insertamos también la última contraseña en texto plano en la columna last_plain_password
    c.execute(
        "INSERT INTO users (username, password, role, dni, email, status, last_plain_password) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (username, password_hash, role, dni, email, status, password)
    )
    conn.commit()
    conn.close()

def validate_file(file):
    if not allowed_file(file.filename):
        return False, "Tipo de archivo no permitido. Solo se permiten PNG, JPG, JPEG y PDF."
    file.seek(0, os.SEEK_END)
    file_length = file.tell()
    file.seek(0)
    if file_length > MAX_FILE_SIZE_MB * 1024 * 1024:
        return False, f"El archivo excede el tamaño máximo de {MAX_FILE_SIZE_MB} MB."
    return True, ""

def save_uploaded_file(file, subfolder=""):
    if file and file.filename != '':
        ok, msg = validate_file(file)
        if not ok:
            return None, msg
        filename = secure_filename(file.filename)
        unique_id = uuid.uuid4().hex
        filename = f"{unique_id}_{filename}"
        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], subfolder) if subfolder else app.config['UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        file.save(os.path.join(upload_dir, filename))
        return filename, ""
    return None, ""

app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'clave_insegura_de_prueba')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

class User(UserMixin):
    def __init__(self, id, username, password, role):
        self.id = id
        self.username = username
        self.password = password
        self.role = role

def init_db():
    """
    Inicializa y migra la base de datos de forma robusta.

    - Crea la tabla users si no existe.
    - Añade columnas faltantes en users (last_plain_password, failed_attempts, created_at) de forma segura.
    - Crea tablas relacionadas: password_resets, password_reset_requests, clients, operations, etc.
    - Inserta usuario admin por defecto si no existe.
    """
    conn = None
    try:
        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()

        # 1) Crear tabla users (schema base). created_at se crea SIN DEFAULT para compatibilidad.
        c.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "username TEXT UNIQUE NOT NULL, "
            "password TEXT NOT NULL, "
            "role TEXT NOT NULL, "
            "dni TEXT, "
            "email TEXT, "
            "status TEXT DEFAULT 'Activo', "
            "created_at TIMESTAMP, "
            "last_login TIMESTAMP, "
            "last_logout TIMESTAMP)"
        )

        # 2) Leer columnas actuales de users
        c.execute("PRAGMA table_info(users)")
        users_cols = [r[1] for r in c.fetchall()]

        # 3) Añadir last_plain_password si falta (nota: inseguro en producción)
        if 'last_plain_password' not in users_cols:
            try:
                c.execute("ALTER TABLE users ADD COLUMN last_plain_password TEXT")
                print("Migración: columna 'last_plain_password' añadida a users")
            except Exception as e:
                print(f"Warning: no se pudo añadir last_plain_password: {e}")

        # 4) Añadir failed_attempts si falta
        if 'failed_attempts' not in users_cols:
            try:
                c.execute("ALTER TABLE users ADD COLUMN failed_attempts INTEGER DEFAULT 0")
                print("Migración: columna 'failed_attempts' añadida a users")
            except Exception as e:
                print(f"Warning: no se pudo añadir failed_attempts: {e}")

        # 5) Añadir created_at si falta (sin DEFAULT) y rellenar filas existentes
        if 'created_at' not in users_cols:
            try:
                c.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP")
                ts = now_peru().strftime('%Y-%m-%d %H:%M:%S')
                c.execute("UPDATE users SET created_at = ? WHERE created_at IS NULL", (ts,))
                print("Migración: columna 'created_at' añadida a users y rellenada")
            except Exception as e:
                print(f"Warning: no se pudo añadir/llenar created_at: {e}")

        # REFRESH users_cols
        c.execute("PRAGMA table_info(users)")
        users_cols = [r[1] for r in c.fetchall()]

        # 6) Tabla para tokens de restablecimiento de contraseña
        c.execute(
            "CREATE TABLE IF NOT EXISTS password_resets ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "user_id INTEGER NOT NULL, "
            "token TEXT NOT NULL UNIQUE, "
            "expires_at TIMESTAMP NOT NULL, "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            "used INTEGER DEFAULT 0, "
            "FOREIGN KEY (user_id) REFERENCES users(id))"
        )

        # 7) Tabla de solicitudes iniciadas desde login para que Masters las atiendan
        c.execute(
            "CREATE TABLE IF NOT EXISTS password_reset_requests ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "user_id INTEGER, "
            "identifier TEXT, "
            "status TEXT DEFAULT 'PENDING', "
            "requested_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            "processed_by INTEGER, "
            "processed_at TIMESTAMP, "
            "notes TEXT)"
        )

        # 8) Tabla trader_stats
        c.execute(
            "CREATE TABLE IF NOT EXISTS trader_stats ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "trader_id INTEGER NOT NULL, "
            "year_month TEXT NOT NULL, "
            "utilidad_dia REAL DEFAULT 0, "
            "utilidad_mes REAL DEFAULT 0, "
            "meta_mes REAL DEFAULT 0, "
            "UNIQUE(trader_id, year_month))"
        )

        # 9) Tabla clients
        c.execute(
            "CREATE TABLE IF NOT EXISTS clients ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "client_id TEXT UNIQUE NOT NULL, "
            "doc_type TEXT NOT NULL, "
            "client_type TEXT NOT NULL, "
            "doc_number TEXT NOT NULL, "
            "name TEXT NOT NULL, "
            "phone TEXT, "
            "email TEXT, "
            "address TEXT, "
            "doc_front TEXT, "
            "doc_back TEXT, "
            "doc_ru TEXT, "
            "status TEXT DEFAULT 'Pendiente', "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            "user_id INTEGER)"
        )

        # Asegurar columna user_id en clients si faltase (compatibilidad con esquemas viejos)
        c.execute("PRAGMA table_info(clients)")
        clients_cols = [r[1] for r in c.fetchall()]
        if 'user_id' not in clients_cols:
            try:
                c.execute("ALTER TABLE clients ADD COLUMN user_id INTEGER")
                print("Migración: columna 'user_id' añadida a clients")
            except Exception as e:
                print(f"Warning: no se pudo añadir user_id a clients: {e}")

        # 10) Tabla bank_accounts
        c.execute(
            "CREATE TABLE IF NOT EXISTS bank_accounts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "client_id INTEGER NOT NULL, "
            "location TEXT NOT NULL, "
            "bank TEXT NOT NULL, "
            "account_type TEXT NOT NULL, "
            "account_number TEXT NOT NULL, "
            "currency TEXT NOT NULL, "
            "FOREIGN KEY (client_id) REFERENCES clients (id))"
        )

        # 11) Tablas client_abonos y client_abono_accounts
        c.execute(
            "CREATE TABLE IF NOT EXISTS client_abonos ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "client_id INTEGER NOT NULL, "
            "doc_type TEXT, "
            "doc_number TEXT, "
            "beneficiary TEXT, "
            "attachment TEXT, "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            "FOREIGN KEY (client_id) REFERENCES clients (id))"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS client_abono_accounts ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "abono_id INTEGER NOT NULL, "
            "location TEXT NOT NULL, "
            "bank TEXT NOT NULL, "
            "account_type TEXT NOT NULL, "
            "account_number TEXT NOT NULL, "
            "currency TEXT NOT NULL, "
            "FOREIGN KEY (abono_id) REFERENCES client_abonos (id))"
        )

        # 12) Tabla qoricash_info_files
        c.execute(
            "CREATE TABLE IF NOT EXISTS qoricash_info_files ("
            "key TEXT PRIMARY KEY, "
            "filename TEXT)"
        )

        # 13) Tabla operations (operaciones)
        c.execute(
            "CREATE TABLE IF NOT EXISTS operations ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "operation_id TEXT UNIQUE NOT NULL, "
            "client_id INTEGER NOT NULL, "
            "operation_type TEXT NOT NULL, "
            "amount_usd REAL NOT NULL, "
            "exchange_rate REAL NOT NULL, "
            "amount_pen REAL NOT NULL, "
            "source_account TEXT NOT NULL, "
            "destination_account TEXT NOT NULL, "
            "status TEXT DEFAULT 'Pendiente', "
            "payment_proof TEXT, "
            "operation_code TEXT, "
            "paid_amount REAL, "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            "updated_at TIMESTAMP, "
            "modificado INTEGER DEFAULT 0, "
            "operador_file TEXT, "
            "operador_comentarios TEXT, "
            "FOREIGN KEY (client_id) REFERENCES clients (id))"
        )

        # Asegurar tabla de secuencia para generar operation_id de forma atómica
        try:
            c.execute("""
                CREATE TABLE IF NOT EXISTS operation_seq (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    last_num INTEGER NOT NULL
                )
            """)
            # Insertar fila inicial si no existe (arranca en 1000, la próxima será 1001)
            c.execute("INSERT OR IGNORE INTO operation_seq (id, last_num) VALUES (1, 1000)")
            print("Migración: tabla 'operation_seq' asegurada")
        except Exception as e:
            print(f"Warning: no se pudo crear operation_seq: {e}")

        # 14) Tablas auxiliares para abonos/pagos y logs
        c.execute(
            "CREATE TABLE IF NOT EXISTS operation_abonos ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "operation_id TEXT NOT NULL, "
            "amount REAL, "
            "nro_operacion TEXT, "
            "comprobante TEXT, "
            "cuenta_cargo TEXT, "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS operation_pagos ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "operation_id TEXT NOT NULL, "
            "amount REAL, "
            "cuenta_destino TEXT, "
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS client_reassign_logs ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "client_id INTEGER NOT NULL, "
            "old_trader_id INTEGER, "
            "new_trader_id INTEGER, "
            "master_user_id INTEGER NOT NULL, "
            "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS operation_logs ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "operation_id TEXT, "
            "action TEXT, "
            "user_id INTEGER, "
            "timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)"
        )

        # 15) Insert admin por defecto si no existe
        try:
            now_ts = now_peru().strftime('%Y-%m-%d %H:%M:%S')
            c.execute(
                "INSERT INTO users (username, password, role, status, created_at) VALUES (?, ?, ?, ?, ?)",
                ('admin', generate_password_hash('admin123'), 'Master', 'Activo', now_ts)
            )
        except sqlite3.IntegrityError:
            # ya existe, ignorar
            pass

        # Commit final
        conn.commit()
        print("Inicialización / migración de la base de datos completada.")
    except Exception as ex:
        print(f"[ERROR init_db] {ex}")
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
    finally:
        if conn:
            conn.close()

@app.route('/uploads/<filename>')
@login_required
def uploaded_operation_file(filename):
    # Sirve cualquier archivo de la carpeta uploads/
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=False)

@csrf.exempt
@app.route('/request_master_reset', methods=['POST'])
def request_master_reset():
    """
    Solicitud desde la pantalla de login: un usuario pide que el Master resetee su contraseña.
    Body JSON: { "identifier": "<username o email>" }
    Comportamiento:
      - Busca user por username o email. Si existe, guarda user_id y identifier en password_reset_requests.
      - Si no existe, igual guarda la request con user_id NULL (para que Master pueda revisar).
      - Emite socketio event 'password_reset_request' con { id, user_id, identifier, requested_at } para notificar Masters.
      - Retorna { success: True, msg: ... }.
    """
    try:
        data = request.get_json(silent=True) or {}
        identifier = (data.get('identifier') or '').strip()
        if not identifier:
            raise BadRequest('Se requiere un identificador (usuario o correo).')

        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()
        # Buscar usuario por username o email (case-insensitive)
        c.execute("SELECT id, username, email, status FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (identifier.lower(), identifier.lower()))
        row = c.fetchone()
        user_id = None
        info = ''
        if row:
            user_id = row[0]
            info = f"Usuario encontrado: {row[1]} (estado: {row[3] or 'N/A'})"
        else:
            info = "Usuario no encontrado en la base; el Master podrá revisar el identificador proporcionado."

        # Insertar solicitud
        try:
            c.execute("INSERT INTO password_reset_requests (user_id, identifier, status) VALUES (?, ?, ?)",
                      (user_id, identifier, 'PENDING'))
            req_id = c.lastrowid
            conn.commit()
        except Exception as e:
            conn.rollback()
            conn.close()
            current_app.logger.error(f"Error insertando password_reset_request: {e}")
            return jsonify(success=False, msg='Error interno al registrar la solicitud'), 500

        # Emitir notificación a Masters mediante Socket.IO
        try:
            payload = {
                'request_id': req_id,
                'user_id': user_id,
                'identifier': identifier,
                'requested_at': now_peru().strftime('%Y-%m-%d %H:%M:%S'),
                'info': info
            }
            # Emitir a todos; en frontend los Masters pueden filtrar por rol
            socketio.emit('password_reset_request', payload, broadcast=True)
        except Exception as e:
            current_app.logger.error(f"Error emitiendo socketio password_reset_request: {e}")

        conn.close()
        return jsonify(success=True, msg='Solicitud enviada. Un Master será notificado.', info=info)

    except BadRequest as br:
        return jsonify(success=False, msg=str(br)), 400
    except Exception as ex:
        current_app.logger.error(f"[request_master_reset] {ex}")
        return jsonify(success=False, msg='Error interno'), 500

@app.route('/eliminar_cliente/<int:client_id>', methods=['POST'])
@login_required
def eliminar_cliente(client_id):
    if getattr(current_user, "role", None) != 'Master':
        return "Solo el Master puede eliminar clientes.", 403
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    # Borra operaciones y cuentas bancarias asociadas antes de borrar cliente
    c.execute("DELETE FROM operations WHERE client_id = ?", (client_id,))
    c.execute("DELETE FROM bank_accounts WHERE client_id = ?", (client_id,))
    c.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()
    socketio.emit('cliente_actualizado', {'tipo': 'actualizado', 'client_id': client_id})
    return jsonify({"success": True})

@app.route('/api/password_reset_requests')
@login_required
def api_password_reset_requests():
    """
    Devuelve la lista de solicitudes de restablecimiento.
    Solo accesible para rol Master.
    Response: { requests: [ { id, user_id, identifier, status, requested_at, processed_by, processed_at, notes } ] }
    """
    if getattr(current_user, "role", None) != 'Master':
        return jsonify({'error': 'No autorizado'}), 403

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("""
        SELECT id, user_id, identifier, status, requested_at, processed_by, processed_at, notes
        FROM password_reset_requests
        ORDER BY requested_at DESC
        LIMIT 200
    """)
    rows = c.fetchall()
    conn.close()

    requests = []
    for r in rows:
        requests.append({
            'id': r[0],
            'user_id': r[1],
            'identifier': r[2],
            'status': r[3],
            'requested_at': r[4],
            'processed_by': r[5],
            'processed_at': r[6],
            'notes': r[7]
        })
    return jsonify({'requests': requests})

@app.route('/admin/process_reset_request', methods=['POST'])
@login_required
def admin_process_reset_request():
    if getattr(current_user, "role", None) != 'Master':
        return jsonify(success=False, msg="No autorizado"), 403

    data = request.get_json(silent=True) or {}
    req_id = data.get('request_id')
    action = (data.get('action') or '').lower()
    notes = data.get('notes', '')

    if not req_id or action not in ('approve', 'reject'):
        return jsonify(success=False, msg='Parámetros inválidos'), 400

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT id, user_id, identifier, status FROM password_reset_requests WHERE id = ?", (req_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify(success=False, msg='Solicitud no encontrada'), 404

    _, user_id, identifier, status_curr = row

    try:
        processed_at = now_peru().strftime('%Y-%m-%d %H:%M:%S')
        if action == 'reject':
            c.execute("UPDATE password_reset_requests SET status = ?, processed_by = ?, processed_at = ?, notes = ? WHERE id = ?",
                      ('REJECTED', current_user.id, processed_at, notes, req_id))
            conn.commit()
            # Emitir evento para UIs que quieran reaccionar
            try:
                socketio.emit('password_reset_processed', {
                    'request_id': req_id,
                    'user_id': user_id,
                    'identifier': identifier,
                    'status': 'REJECTED',
                    'processed_by': current_user.id,
                    'processed_at': processed_at,
                    'notes': notes
                }, broadcast=True)
            except Exception:
                pass
            conn.close()
            return jsonify(success=True, msg='Solicitud rechazada')

        # action == 'approve'
        if not user_id:
            conn.close()
            return jsonify(success=False, msg='La solicitud no tiene usuario asociado en la base de datos. Revísalo antes de aprobar.'), 400

        # Generar contraseña temporal segura
        temp_plain = 'tmp' + uuid.uuid4().hex[:8]
        temp_hash = generate_password_hash(temp_plain)

        # Actualizar usuario: password, last_plain_password, failed_attempts=0, status='Activo'
        c.execute("UPDATE users SET password = ?, last_plain_password = ?, failed_attempts = 0, status = 'Activo' WHERE id = ?",
                  (temp_hash, temp_plain, user_id))

        # Marcar solicitud como DONE
        c.execute("UPDATE password_reset_requests SET status = ?, processed_by = ?, processed_at = ?, notes = ? WHERE id = ?",
                  ('DONE', current_user.id, processed_at, notes or 'Aprobado por Master', req_id))

        conn.commit()

        # Emitir evento para solicitudes
        try:
            socketio.emit('password_reset_processed', {
                'request_id': req_id,
                'user_id': user_id,
                'identifier': identifier,
                'status': 'DONE',
                'processed_by': current_user.id,
                'processed_at': processed_at,
                'notes': notes or ''
            }, broadcast=True)
        except Exception:
            pass

        # Emitir evento user_updated para que los Masters conectados actualicen la tabla de usuarios
        try:
            socketio.emit('user_updated', {
                'user_id': user_id,
                'last_plain_password': temp_plain,
                'status': 'Activo',
                'failed_attempts': 0
            }, broadcast=True)
        except Exception:
            pass

        conn.close()
        return jsonify(success=True, msg='Solicitud aprobada. Contraseña temporal generada.', temporary_password=temp_plain)

    except Exception as e:
        conn.rollback()
        conn.close()
        current_app.logger.error(f"[admin_process_reset_request] {e}")
        return jsonify(success=False, msg='Error interno procesando la solicitud'), 500

@app.route('/eliminar_operacion/<operation_id>', methods=['POST'])
@login_required
def eliminar_operacion(operation_id):
    if getattr(current_user, "role", None) != 'Master':
        return "Solo el Master puede eliminar operaciones.", 403
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("DELETE FROM operations WHERE operation_id = ?", (operation_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route('/api/operation/<operation_id>/devolver_pendiente', methods=['POST'])
@login_required
def devolver_operacion_pendiente(operation_id):
    print(f"[DEBUG] Entrando al endpoint devolver_op_pendiente para {operation_id}")
    # Permitir Operador y Master
    if current_user.role not in ('Operador', 'Master'):
        print(f"[DEBUG] No autorizado: role={getattr(current_user, 'role', None)}")
        return jsonify({'error': 'No autorizado'}), 403

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT status FROM operations WHERE operation_id = ?", (operation_id,))
    row = c.fetchone()
    status_raw = row[0] if row and row[0] else ""
    import unicodedata
    def normalize(s):
        if not s: return ""
        # Elimina acentos, convierte a minúsculas, remueve espacios laterales
        return ''.join(c for c in unicodedata.normalize('NFD', s) if unicodedata.category(c) != 'Mn').strip().lower()
    status = normalize(status_raw)
    print(f"[DEBUG] Status actual: '{status_raw}' | Normalizado: '{status}'")
    if status not in ['en proceso', 'p-en proceso']:
        print(f"[DEBUG] Estado no permitido: '{status}'")
        conn.close()
        return jsonify({'error': f'Solo se puede devolver operaciones En proceso. Estado actual: "{status_raw}"'}), 400

    # Actualizar estado a Pendiente
    try:
        c.execute("UPDATE operations SET status = 'Pendiente', updated_at = ? WHERE operation_id = ?", (now_peru().strftime('%Y-%m-%d %H:%M:%S'), operation_id))
        # Registrar en logs (si la tabla existe)
        try:
            c.execute("INSERT INTO operation_logs (operation_id, action, user_id, timestamp) VALUES (?, ?, ?, ?)",
                      (operation_id, 'devuelto_a_pendiente', current_user.id, now_peru().strftime('%Y-%m-%d %H:%M:%S')))
        except Exception as e_log:
            # No interrumpir si no existe la tabla de logs o falla el insert; registrar en stdout para debugging
            print(f"[DEBUG] No se pudo insertar en operation_logs: {e_log}")
        conn.commit()
        print("[DEBUG] Estado actualizado a Pendiente")
    except Exception as e:
        conn.rollback()
        print(f"[DEBUG] Error actualizando estado: {e}")
        conn.close()
        return jsonify({'error': 'Error interno al actualizar la operación'}), 500

    conn.close()
    print("[DEBUG] Commit realizado correctamente")
    return jsonify({'success': True})

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_data = c.fetchone()
    conn.close()
    if user_data:
        return User(id=user_data[0], username=user_data[1], password=user_data[2], role=user_data[3])
    return None

def generar_idop(conn, retries=5):
    """
    Genera un nuevo ID de operación tipo EXP-XXXX de forma segura contra
    condiciones de carrera usando una tabla operation_seq y BEGIN IMMEDIATE en SQLite.
    Si falla (p. ej. tabla no existe o se agota reintentos) cae en el método antiguo.
    """
    # Intento atómico usando operation_seq
    try:
        for attempt in range(retries):
            try:
                # Iniciar transacción inmediata para bloquear escritura y asegurar atomicidad
                conn.execute('BEGIN IMMEDIATE')
                c = conn.cursor()
                c.execute("SELECT last_num FROM operation_seq WHERE id = 1")
                row = c.fetchone()
                if row and row[0] is not None:
                    last_num = int(row[0])
                else:
                    last_num = 1000
                    c.execute("INSERT OR REPLACE INTO operation_seq (id, last_num) VALUES (1, ?)", (last_num,))
                new_num = last_num + 1
                c.execute("UPDATE operation_seq SET last_num = ? WHERE id = 1", (new_num,))
                conn.commit()
                return f"EXP-{new_num:04d}"
            except sqlite3.OperationalError as op_err:
                # DB locked o similar; deshacer e intentar de nuevo con backoff
                try:
                    conn.rollback()
                except Exception:
                    pass
                # Small linear backoff
                time.sleep(0.05 * (attempt + 1))
                continue
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise
    except Exception:
        # Si algo no funcionó con operation_seq, continuamos con fallback abajo
        try:
            conn.rollback()
        except Exception:
            pass

    # FALLBACK: comportamiento antiguo (leer última operación y sumar 1)
    c = conn.cursor()
    c.execute("SELECT operation_id FROM operations WHERE operation_id LIKE 'EXP-%' ORDER BY LENGTH(operation_id) DESC, operation_id DESC LIMIT 1")
    last = c.fetchone()
    if last and last[0].startswith("EXP-"):
        try:
            last_num = int(last[0].split('-')[1])
        except Exception:
            last_num = 1000
        new_num = last_num + 1
    else:
        new_num = 1001
    return f"EXP-{new_num:04d}"

@app.route('/')
def index():
    return redirect(url_for('login'))

# ... rest of file remains unchanged ...

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
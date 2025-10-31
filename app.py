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
        return jsonify({'error': f'Solo se puede devolver operaciones En proceso. Estado actual: \"{status_raw}\"'}), 400

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
                # Small backoff (exponencial lineal)
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

@app.route('/api/traders_list')
@login_required
def api_traders_list():
    """
    Devuelve la lista de traders activos (id, username).
    Solo Master puede usarlo.
    """
    if getattr(current_user, "role", None) != 'Master':
        return jsonify({'error': 'No autorizado'}), 403
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE role = 'Trader' AND status = 'Activo' ORDER BY username")
    rows = c.fetchall()
    conn.close()
    traders = [{'id': r[0], 'username': r[1]} for r in rows]
    return jsonify({'traders': traders})

@app.route('/api/trader_clients/<int:trader_id>')
@login_required
def api_trader_clients(trader_id):
    """
    Devuelve los clientes asignados a un trader (internos id y campos para mostrar).
    Solo Master puede usarlo.
    """
    if getattr(current_user, "role", None) != 'Master':
        return jsonify({'error': 'No autorizado'}), 403

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("""SELECT id, client_id, name, doc_number, status, created_at
                 FROM clients
                 WHERE user_id = ?
                 ORDER BY created_at DESC""", (trader_id,))
    rows = c.fetchall()
    conn.close()
    clients = []
    for r in rows:
        clients.append({
            'id': r[0],
            'client_id': r[1],
            'name': r[2],
            'doc_number': r[3],
            'status': r[4],
            'created_at': r[5]
        })
    return jsonify({'clients': clients})

@app.route('/api/reassign_clients', methods=['POST'])
@login_required
def api_reassign_clients():
    """
    Reasigna una lista de clientes (IDs internos) a un nuevo trader.
    Solo Master puede ejecutar.
    Request JSON: { "client_ids": [1,2,3], "new_trader_id": 5 }
    Respuesta JSON: { success: True, reassigned: N, skipped: M, errors: [...] }
    """
    if getattr(current_user, "role", None) != 'Master':
        return jsonify({'error': 'No autorizado'}), 403

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': 'JSON inválido o faltante'}), 400

    client_ids = data.get('client_ids', [])
    new_trader_id = data.get('new_trader_id')

    if not isinstance(client_ids, list) or not client_ids:
        return jsonify({'error': 'Debe indicar una lista de client_ids'}), 400
    if not new_trader_id:
        return jsonify({'error': 'Debe indicar new_trader_id'}), 400

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Validar que el trader destino existe y es Trader
    c.execute("SELECT role, status FROM users WHERE id = ?", (new_trader_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Trader destino no encontrado'}), 404
    role_dest, status_dest = row[0], row[1]
    if role_dest != 'Trader':
        conn.close()
        return jsonify({'error': 'El usuario destino no es un Trader válido'}), 400
    if status_dest != 'Activo':
        conn.close()
        return jsonify({'error': 'El trader destino no está activo'}), 400

    reassigned_count = 0
    skipped_count = 0
    errors = []
    reassigned_clients_public_ids = []

    try:
        for cid in client_ids:
            try:
                # Obtener cliente actual
                c.execute("SELECT id, client_id, user_id FROM clients WHERE id = ?", (cid,))
                cl = c.fetchone()
                if not cl:
                    skipped_count += 1
                    errors.append({'client_id': cid, 'error': 'Cliente no encontrado'})
                    continue
                internal_id, public_client_id, old_trader_id = cl[0], cl[1], cl[2]
                if old_trader_id == new_trader_id:
                    skipped_count += 1
                    continue

                # Actualizar cliente
                c.execute("UPDATE clients SET user_id = ? WHERE id = ?", (new_trader_id, internal_id))

                # Guardar log en client_reassign_logs
                c.execute("""
                    INSERT INTO client_reassign_logs (client_id, old_trader_id, new_trader_id, master_user_id)
                    VALUES (?, ?, ?, ?)
                """, (internal_id, old_trader_id, new_trader_id, current_user.id))

                # Emitir evento por socket para actualizar UIs conectadas
                # Emitimos el client public id para que clientes en frontend puedan refresh si lo necesitan
                try:
                    socketio.emit('cliente_actualizado', {
                        'tipo': 'reasignado',
                        'client_id': public_client_id,
                        'old_trader_id': old_trader_id,
                        'new_trader_id': new_trader_id
                    })
                except Exception:
                    # No interrumpir si SocketIO falla
                    pass

                reassigned_count += 1
                reassigned_clients_public_ids.append(public_client_id)
            except Exception as e_inner:
                skipped_count += 1
                errors.append({'client_id': cid, 'error': str(e_inner)})
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': 'Error interno al reasignar', 'details': str(e)}), 500

    conn.close()
    return jsonify({
        'success': True,
        'reassigned': reassigned_count,
        'skipped': skipped_count,
        'errors': errors,
        'client_ids': reassigned_clients_public_ids
    })

@app.route('/get_csrf_token')
@login_required
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_input = request.form['username'].strip()
        password = request.form['password']
        remember = request.form.get('remember') in ('on', 'true', '1')

        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()
        # Intentar buscar por username o email (case-insensitive)
        c.execute("SELECT id, username, password, role, status, failed_attempts, email FROM users WHERE LOWER(username) = ? OR LOWER(email) = ?", (username_input.lower(), username_input.lower()))
        user_data = c.fetchone()

        if user_data:
            user_id_db, username_db, pw_hash, role_db, status_db, failed_attempts_db, email_db = user_data[0], user_data[1], user_data[2], user_data[3], user_data[4], user_data[5] or 0, user_data[6]
            # Si la cuenta ya está inactiva, mostrar mensaje y negar acceso
            if status_db is not None and status_db == 'Inactivo':
                conn.close()
                flash('Su cuenta está inactiva. Comuníquese con el administrador.')
                return render_template('login.html', user=None)

            if check_password_hash(pw_hash, password):
                # Login correcto -> resetear failed_attempts y proceder
                try:
                    c.execute("UPDATE users SET failed_attempts = 0, last_login = ? WHERE id = ?", (now_peru().strftime("%Y-%m-%d %H:%M:%S"), user_id_db))
                    conn.commit()
                except Exception:
                    pass
                conn.close()
                user = User(id=user_id_db, username=username_db, password=pw_hash, role=role_db)
                login_user(user, remember=remember)
                return redirect(url_for('dashboard'))
            else:
                # Contraseña incorrecta -> incrementar contador y manejar mensajes
                new_failed = (failed_attempts_db or 0) + 1
                try:
                    # Si alcanza 3 -> poner estado Inactivo
                    if new_failed >= 3:
                        c.execute("UPDATE users SET failed_attempts = ?, status = 'Inactivo' WHERE id = ?", (new_failed, user_id_db))
                        conn.commit()
                        conn.close()
                        # Mostrar mensaje de cuenta inactiva
                        flash('Su cuenta ha sido inactivada tras 3 intentos fallidos. No puede acceder, comuníquese con el administrador.')
                        return render_template('login.html', user=None)
                    else:
                        c.execute("UPDATE users SET failed_attempts = ? WHERE id = ?", (new_failed, user_id_db))
                        conn.commit()
                except Exception:
                    pass

                # Si es el primer intento fallido (antes de incrementar era 0) -> mensaje preventivo
                if failed_attempts_db == 0:
                    flash('Contraseña incorrecta. Tenga en cuenta que al tercer intento errado la cuenta estará inactiva.')
                else:
                    flash(f'Contraseña incorrecta. Intentos fallidos: {new_failed} de 3.')

                conn.close()
                return render_template('login.html', user=None)

        else:
            # Usuario no existe -> comportamiento por seguridad: no revelamos si no existe.
            # Podemos mostrar mensaje genérico. No incrementamos contadores.
            flash('Usuario o contraseña incorrectos')
            return render_template('login.html', user=None)

    return render_template('login.html', user=None)
@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    """
    Body JSON: { "email": "user@..." }
    - Crea un token y lo guarda en password_resets con expiración (1 hora).
    - En producción DEBES enviar el token por email; aquí devolvemos el token en JSON para pruebas.
    """
    data = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()
    if not email:
        return jsonify(success=False, msg='Correo requerido'), 400

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE LOWER(email) = ?", (email,))
    row = c.fetchone()
    if not row:
        conn.close()
        # No revelar existencia del email: devolvemos éxito genérico
        return jsonify(success=True, msg='Si el correo existe recibirá instrucciones.'), 200

    user_id = row[0]
    token = uuid.uuid4().hex
    expires = (now_peru() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
    try:
        c.execute("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)", (user_id, token, expires))
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify(success=False, msg='Error interno'), 500

    conn.close()

    # En producción: envía email con token aquí.
    # Para pruebas: devolvemos token en JSON (el frontend muestra el token en la alerta)
    return jsonify(success=True, msg='Código generado. Revisa tu correo (en pruebas se muestra a continuación).', token=token)

@app.route('/perform_password_reset', methods=['POST'])
def perform_password_reset():
    data = request.get_json(silent=True) or {}
    token = data.get('token', '').strip()
    new_password = data.get('new_password', '').strip()
    email = data.get('email', '').strip().lower()

    if not token or not new_password:
        return jsonify(success=False, msg='Token y nueva contraseña son requeridos'), 400
    if len(new_password) < 8 or not any(ch.isdigit() for ch in new_password):
        return jsonify(success=False, msg='La contraseña debe tener al menos 8 caracteres y un número'), 400

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    c.execute("SELECT id, user_id, expires_at, used FROM password_resets WHERE token = ?", (token,))
    pr = c.fetchone()
    if not pr:
        conn.close()
        return jsonify(success=False, msg='Token inválido'), 404
    pr_id, user_id, expires_at, used = pr[0], pr[1], pr[2], pr[3]
    if used:
        conn.close()
        return jsonify(success=False, msg='Token ya usado'), 400
    try:
        exp_dt = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S')
    except Exception:
        conn.close()
        return jsonify(success=False, msg='Token inválido'), 400
    if now_peru() > exp_dt:
        conn.close()
        return jsonify(success=False, msg='Token expirado'), 400

    if email:
        c.execute("SELECT email FROM users WHERE id = ?", (user_id,))
        urow = c.fetchone()
        if not urow or (urow[0] and urow[0].lower() != email.lower()):
            conn.close()
            return jsonify(success=False, msg='Token no corresponde al correo indicado'), 400

    new_hash = generate_password_hash(new_password)
    try:
        c.execute("UPDATE users SET password = ?, last_plain_password = ?, failed_attempts = 0, status = 'Activo' WHERE id = ?", (new_hash, new_password, user_id))
        c.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (pr_id,))
        conn.commit()
        # Emitir evento para que UIs actualicen la fila del usuario en tiempo real
        try:
            socketio.emit('user_updated', {
                'user_id': user_id,
                'last_plain_password': new_password,
                'status': 'Activo',
                'failed_attempts': 0
            }, broadcast=True)
        except Exception:
            pass
    except Exception as e:
        conn.close()
        return jsonify(success=False, msg='Error al guardar nueva contraseña'), 500

    conn.close()
    return jsonify(success=True, msg='Contraseña restablecida correctamente')

@app.route('/api/search_users')
@login_required
def api_search_users():
    q = request.args.get('q', '').strip().lower()
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    if q:
        c.execute("""
            SELECT id, username, dni, email, role, status, created_at, last_login, last_logout
            FROM users
            WHERE LOWER(username) LIKE ? OR LOWER(COALESCE(dni, '')) LIKE ? OR LOWER(email) LIKE ?
            ORDER BY created_at DESC
        """, (f'%{q}%', f'%{q}%', f'%{q}%'))
    else:
        c.execute("""
            SELECT id, username, dni, email, role, status, created_at, last_login, last_logout
            FROM users
            ORDER BY created_at DESC
        """)
    users = c.fetchall()
    conn.close()
    result = []
    for u in users:
        result.append({
            "id": u[0],
            "username": u[1],
            "dni": u[2],
            "email": u[3],
            "role": u[4],
            "status": u[5],
            "created_at": u[6],
            "last_login": u[7],
            "last_logout": u[8],
        })
    return jsonify(result)

@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    if current_user.role != 'Master':
        return jsonify(msg="No tienes permisos para eliminar usuarios."), 403

    data = request.get_json()
    email = data.get('email', '').strip().lower()
    if not email:
        return jsonify(msg="Debes ingresar un correo válido."), 400

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE LOWER(email)=?", (email,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify(msg="No existe un usuario con ese correo."), 404

    if email == 'admin@admin.com' or row[0] == 1:
        conn.close()
        return jsonify(msg="No se puede eliminar el usuario master."), 403

    c.execute("DELETE FROM users WHERE id=?", (row[0],))
    conn.commit()
    conn.close()
    return jsonify(msg="Usuario eliminado correctamente.")

@app.route('/logout')
@login_required
def logout():
    # ---- Actualizar last_logout ----
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("UPDATE users SET last_logout = ? WHERE id = ?", (now_peru().strftime("%Y-%m-%d %H:%M:%S"), current_user.id))
    conn.commit()
    conn.close()
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/operation/<operation_id>/actualizar_cuentas', methods=['POST'])
@login_required
def actualizar_cuentas_operacion(operation_id):
    if current_user.role not in ('Trader', 'Master'):
        return jsonify({"error": "No autorizado"}), 403
    
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    
    # Verificar que la operación existe y está en estado Pendiente
    c.execute("SELECT status FROM operations WHERE operation_id = ?", (operation_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Operación no encontrada"}), 404
    
    if row[0] != "Pendiente":
        conn.close()
        return jsonify({"error": "Solo se pueden modificar cuentas en operaciones Pendientes"}), 400
    
    source_account = request.form.get('source_account')
    destination_account = request.form.get('destination_account')
    
    if not source_account or not destination_account:
        conn.close()
        return jsonify({"error": "Faltan datos de cuentas"}), 400
    
    # Actualizar las cuentas
    c.execute('''UPDATE operations 
                 SET source_account = ?, destination_account = ?, updated_at = ?
                 WHERE operation_id = ?''',
              (source_account, destination_account, now_peru().strftime('%Y-%m-%d %H:%M:%S'), operation_id))
    
    conn.commit()
    conn.close()
    socketio.emit('operacion_actualizada', {'tipo': 'actualizada', 'operation_id': operation_id})
    return jsonify({"success": True})
	
@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    today = now_peru().strftime('%Y-%m-%d')
    first_day_month = now_peru().replace(day=1).strftime('%Y-%m-%d')

    if current_user.role == 'Trader':
        c.execute("SELECT COUNT(*) FROM clients WHERE user_id = ?", (current_user.id,))
        clients_month = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM clients WHERE user_id = ? AND DATE(created_at) = ?", (current_user.id, today))
        clients_today = c.fetchone()[0]

        c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0)
                     FROM operations
                     WHERE client_id IN (SELECT id FROM clients WHERE user_id = ?)
                       AND DATE(created_at) = ?
                       	""", (current_user.id, today))
        operations_today, usd_today, pen_today = c.fetchone()
        c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0)
                     FROM operations
                     WHERE client_id IN (SELECT id FROM clients WHERE user_id = ?)
                       AND DATE(created_at) >= ?
                       AND status NOT IN ('Cancelada', 'Anulada')""", (current_user.id, first_day_month))
        operations_month, usd_month, pen_month = c.fetchone()

        c.execute("""
            SELECT o.*, c.name, c.doc_number
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            WHERE c.user_id = ? AND DATE(o.created_at) = ? AND o.status = 'Pendiente'
            ORDER BY o.created_at DESC
        """, (current_user.id, today))
        pending_operations = c.fetchall()

        conn.close()

        return render_template('trader_dashboard.html',
                               user=current_user,
                               clients_today=clients_today,
                               clients_month=clients_month,
                               operations_today=operations_today,
                               operations_month=operations_month,
                               usd_today=usd_today,
                               usd_month=usd_month,
                               pen_today=pen_today,
                               pen_month=pen_month,
                               pending_operations=pending_operations)
    else:
        c.execute("SELECT COUNT(*) FROM clients WHERE DATE(created_at) = ?", (today,))
        clients_today = c.fetchone()[0] or 0

        c.execute("SELECT COUNT(*) FROM clients WHERE DATE(created_at) >= ?", (first_day_month,))
        clients_month = c.fetchone()[0] or 0

        c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0)
                     FROM operations
                     WHERE DATE(created_at) = ?
                       AND status NOT IN ('Cancelada', 'Anulada')""", (today,))
        operations_today, usd_today, pen_today = c.fetchone()

        c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0)
                     FROM operations
                     WHERE DATE(created_at) >= ?
                       AND status NOT IN ('Cancelada', 'Anulada')""", (first_day_month,))
        operations_month, usd_month, pen_month = c.fetchone()

        c.execute("""
            SELECT o.*, c.name, c.doc_number
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            WHERE DATE(o.created_at) = ? AND o.status = 'Pendiente'
            ORDER BY o.created_at DESC
        """, (today,))
        pending_operations = c.fetchall()

        conn.close()

        return render_template('dashboard.html',
                               user=current_user,
                               clients_today=clients_today,
                               clients_month=clients_month,
                               operations_today=operations_today,
                               operations_month=operations_month,
                               usd_today=usd_today,
                               usd_month=usd_month,
                               pen_today=pen_today,
                               pen_month=pen_month,
                               pending_operations=pending_operations)
@app.route('/check_document', methods=['POST'])
def check_document():
    doc_number = request.form['doc_number']
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM clients WHERE doc_number = ?", (doc_number,))
    count = c.fetchone()[0]
    conn.close()
    return jsonify({'exists': count > 0})

@app.route('/register_client', methods=['POST'])
@login_required
def register_client():
    # Este endpoint solo acepta POST AJAX. No renderiza HTML.
    # Si se recibe GET, devolver 405 o redirigir.
    if request.method == 'GET':
        return redirect(url_for('gestion_clientes'))

    # Soporta tanto application/json (AJAX) como multipart/form-data (archivos, si es necesario)
    if request.is_json:
        data = request.get_json()
        doc_type = data.get('doc_type')
        client_type = data.get('client_type') or ('Jurídica' if doc_type == 'RUC' else 'Natural')
        doc_number = data.get('doc_number')
        name = data.get('name')
        phone = data.get('phone')
        email = data.get('email')
        address = data.get('address')
        # abono en JSON (si fuera enviado así)
        abono_doc_type = data.get('abono_doc_type', None)
        abono_doc_number = data.get('abono_doc_number', None)
        abono_beneficiary = data.get('abono_beneficiary', None)
        abono_accounts = data.get('abono_accounts', [])  # array de objetos
        # nota: en JSON no manejamos archivos binarios en este endpoint
    else:
        # Para multipart (compatibilidad con el formulario)
        doc_type = request.form.get('doc_type')
        client_type = request.form.get('client_type') or ('Jurídica' if doc_type == 'RUC' else 'Natural')
        doc_number = request.form.get('doc_number')
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        address = request.form.get('address')
        # Abono a terceros (si el trader marco la sección, vendrán estos campos)
        abono_doc_type = request.form.get('abono_doc_type', None)
        abono_doc_number = request.form.get('abono_doc_number', None)
        abono_beneficiary = request.form.get('abono_beneficiary', None)
        # cuentas abono (listas)
        abono_account_locations = request.form.getlist('abono_account_location[]')
        abono_account_banks = request.form.getlist('abono_account_bank[]')
        abono_account_types = request.form.getlist('abono_account_type[]')
        abono_account_currencies = request.form.getlist('abono_account_currency[]')
        abono_account_numbers = request.form.getlist('abono_account_number[]')
        abono_accounts = []
        for i in range(len(abono_account_locations)):
            abono_accounts.append({
                'location': abono_account_locations[i],
                'bank': abono_account_banks[i] if i < len(abono_account_banks) else '',
                'account_type': abono_account_types[i] if i < len(abono_account_types) else '',
                'currency': abono_account_currencies[i] if i < len(abono_account_currencies) else '',
                'account_number': abono_account_numbers[i] if i < len(abono_account_numbers) else ''
            })

    # Verificar si el documento ya existe
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Nuevo comportamiento: permitir crear un nuevo cliente con mismo número de documento
    # SOLO si todos los registros existentes con ese número tienen estado = 'Rechazado'.
    c.execute("SELECT status FROM clients WHERE doc_number = ?", (doc_number,))
    rows = c.fetchall()
    if rows:
        # Si existe al menos un registro y alguno NO está en 'Rechazado', bloquear
        for r in rows:
            existing_status = r[0] if r and len(r) > 0 else None
            if existing_status is None or existing_status != 'Rechazado':
                conn.close()
                return jsonify({'success': False, 'error': 'El número de documento ya está registrado'})
        # Si llegamos aquí significa que todos los registros (uno o varios) están en 'Rechazado'
        # y por tanto permitimos continuar con el registro de un nuevo cliente.

    # Generar ID único de cliente con formato P00001
    c.execute("SELECT MAX(CAST(SUBSTR(client_id, 2) AS INTEGER)) FROM clients")
    last_id = c.fetchone()[0]
    if last_id is None:
        new_id = 1
    else:
        new_id = last_id + 1
    client_id = 'P' + str(new_id).zfill(5)

    doc_front = None
    doc_back = None
    doc_ru = None

    # Archivos principales (doc_front, doc_back, doc_ru)
    if 'doc_front' in request.files:
        file = request.files['doc_front']
        filename, msg = save_uploaded_file(file, subfolder="clientes")
        if msg:
            flash(msg)
            conn.close()
            return jsonify({'success': False, 'error': msg})
        if filename:
            doc_front = filename

    if 'doc_back' in request.files:
        file = request.files['doc_back']
        filename, msg = save_uploaded_file(file, subfolder="clientes")
        if msg:
            flash(msg)
            conn.close()
            return jsonify({'success': False, 'error': msg})
        if filename:
            doc_back = filename

    if 'doc_ru' in request.files:
        file = request.files['doc_ru']
        filename, msg = save_uploaded_file(file, subfolder="clientes")
        if msg:
            flash(msg)
            conn.close()
            return jsonify({'success': False, 'error': msg})
        if filename:
            doc_ru = filename

    # Guardar en base de datos (cliente)
    try:
        c.execute('''INSERT INTO clients 
                    (client_id, doc_type, client_type, doc_number, name, phone, email, address, doc_front, doc_back, doc_ru, user_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                    (client_id, doc_type, client_type, doc_number, name, phone, email, address, doc_front, doc_back, doc_ru, current_user.id))
        client_db_id = c.lastrowid
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify({'success': False, 'error': 'Error al insertar cliente: ' + str(e)}), 500

    # Procesar cuentas bancarias del cliente (las "normales")
    if request.is_json:
        bank_accounts = data.get('bank_accounts', [])
        has_soles = False
        has_dollars = False
        for acc in bank_accounts:
            if acc.get('location') and acc.get('bank') and acc.get('account_type') and acc.get('account_number') and acc.get('currency'):
                c.execute('''INSERT INTO bank_accounts 
                          (client_id, location, bank, account_type, account_number, currency)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                          (client_db_id, acc['location'], acc['bank'], acc['account_type'], acc['account_number'], acc['currency']))
                if acc['currency'] == 'Soles':
                    has_soles = True
                elif acc['currency'] == 'Dólares':
                    has_dollars = True
    else:
        # Para multipart (no deberías necesitarlo)
        account_locations = request.form.getlist('account_location[]')
        account_banks = request.form.getlist('account_bank[]')
        account_types = request.form.getlist('account_type[]')
        account_numbers = request.form.getlist('account_number[]')
        account_currencies = request.form.getlist('account_currency[]')
        has_soles = False
        has_dollars = False
        for i in range(len(account_locations)):
            if account_locations[i] and account_banks[i] and account_types[i] and account_numbers[i] and account_currencies[i]:
                c.execute('''INSERT INTO bank_accounts 
                          (client_id, location, bank, account_type, account_number, currency)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                          (client_db_id, account_locations[i], account_banks[i], account_types[i], account_numbers[i], account_currencies[i]))
                if account_currencies[i] == 'Soles':
                    has_soles = True
                elif account_currencies[i] == 'Dólares':
                    has_dollars = True

    # Verificar que tenga al menos una cuenta en soles y una en dólares
    if not (has_soles and has_dollars):
        conn.rollback()
        conn.close()
        return jsonify({'success': False, 'error': 'El cliente debe tener al menos una cuenta en Soles y una en Dólares'})

    # --------------------------
    # PROCESAR ABONO A TERCEROS (si fue enviado)
    # --------------------------
    # Determinamos que hay abono si abono_doc_type está presente (form) o si en JSON viene abono_doc_type
    try:
        if abono_doc_type:
            # Validaciones básicas
            # Normalizar campos
            abono_doc_type = abono_doc_type.strip() if isinstance(abono_doc_type, str) else abono_doc_type
            abono_doc_number = abono_doc_number.strip() if isinstance(abono_doc_number, str) else (abono_doc_number or '')
            abono_beneficiary = abono_beneficiary.strip() if isinstance(abono_beneficiary, str) else (abono_beneficiary or '')

            # Validar longitud de documento
            def _expected_len_for(tipo):
                if tipo == 'DNI': return 8
                if tipo == 'Carnet de Extranjería': return 9
                if tipo == 'RUC': return 11
                return None

            exp_len = _expected_len_for(abono_doc_type)
            if not abono_doc_type or not abono_doc_number or not abono_beneficiary:
                conn.rollback()
                conn.close()
                return jsonify({'success': False, 'error': 'Faltan campos requeridos en Abono a terceros'}), 400
            if exp_len and len(abono_doc_number) != exp_len:
                conn.rollback()
                conn.close()
                return jsonify({'success': False, 'error': f'Longitud inválida para documento de abono (esperado {exp_len})'}), 400

            # Validar cuentas abono (al menos una completa)
            okCuenta = False
            for acc in abono_accounts:
                if acc.get('location') and acc.get('bank') and acc.get('account_type') and acc.get('account_number') and acc.get('currency'):
                    okCuenta = True
                    break
            if not okCuenta:
                conn.rollback()
                conn.close()
                return jsonify({'success': False, 'error': 'Debe agregar al menos una cuenta bancaria válida para Abono a terceros'}), 400

            # Validar archivo adjunto (solo si multipart)
            abono_attachment_filename = None
            if not request.is_json:
                if 'abono_attachment' not in request.files or request.files['abono_attachment'].filename == '':
                    conn.rollback()
                    conn.close()
                    return jsonify({'success': False, 'error': 'Debe adjuntar el comprobante de abono a terceros'}), 400
                file = request.files['abono_attachment']
                filename, msg = save_uploaded_file(file, subfolder="clientes/abonos")
                if msg:
                    conn.rollback()
                    conn.close()
                    return jsonify({'success': False, 'error': msg}), 400
                abono_attachment_filename = filename
            else:
                # Si vino en JSON, no hay soporte de archivo binario en este endpoint en JSON mode
                conn.rollback()
                conn.close()
                return jsonify({'success': False, 'error': 'El archivo de abono debe enviarse como multipart/form-data'}), 400

            # Insertar registro de abono
            c.execute('''INSERT INTO client_abonos (client_id, doc_type, doc_number, beneficiary, attachment)
                         VALUES (?, ?, ?, ?, ?)''',
                      (client_db_id, abono_doc_type, abono_doc_number, abono_beneficiary, abono_attachment_filename))
            abono_id = c.lastrowid

            # Insertar cuentas de abono
            for acc in abono_accounts:
                if acc.get('location') and acc.get('bank') and acc.get('account_type') and acc.get('account_number') and acc.get('currency'):
                    c.execute('''INSERT INTO client_abono_accounts
                                 (abono_id, location, bank, account_type, account_number, currency)
                                 VALUES (?, ?, ?, ?, ?, ?)''',
                              (abono_id, acc['location'], acc['bank'], acc['account_type'], acc['account_number'], acc['currency']))
    except Exception as e_ab:
        conn.rollback()
        conn.close()
        return jsonify({'success': False, 'error': 'Error procesando Abono a terceros: ' + str(e_ab)}), 500

    # Todo OK → commit y cerrar
    conn.commit()
    conn.close()

    # Emitir evento y notificación como ya estaba antes (client_id público)
    socketio.emit('cliente_actualizado', {'tipo': 'actualizado', 'client_id': client_id})

    # NUEVO: Emitir notificación para operadores
    socketio.emit('notificacion_operador', {
        'tipo': 'nuevo_cliente',
        'mensaje': f'Nuevo cliente registrado: {name}',
        'client_id': client_id,
        'cliente': name,
        'doc_number': doc_number,
        'timestamp': now_peru().strftime('%H:%M:%S')
    })
    return jsonify({'success': True})

@app.route('/gestion_clientes')
@login_required
def gestion_clientes():
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Verifica si tienes la columna user_id en clients
    c.execute("PRAGMA table_info(clients)")
    columns = [col[1] for col in c.fetchall()]

    if 'user_id' in columns and hasattr(current_user, 'role'):
        if current_user.role == 'Trader':
            query = '''SELECT c.*, u.username 
                       FROM clients c 
                       LEFT JOIN users u ON c.user_id = u.id 
                       WHERE c.user_id = ? 
                       ORDER BY c.created_at DESC'''
            params = [current_user.id]
        else:
            query = '''SELECT c.*, u.username 
                       FROM clients c 
                       LEFT JOIN users u ON c.user_id = u.id 
                       ORDER BY c.created_at DESC'''
            params = []
    else:
        query = "SELECT *, NULL as username FROM clients ORDER BY created_at DESC"
        params = []

    c.execute(query, params)
    clients = c.fetchall()
    conn.close()
    return render_template('gestion_clientes.html', clients=clients, user=current_user)

@app.route('/validate_password', methods=['POST'])
@login_required
def validate_password():
    """
    Valida la contraseña actual de un usuario. Acepta JSON o form-urlencoded.
    Request:
      - user_id (opcional): si no se envía, se asume current_user.id
      - password: contraseña a validar
    Response JSON:
      - { ok: True } si coincide
      - { ok: False, msg: '...'} si no coincide o hay error
    """
    try:
        data = request.get_json(silent=True) or request.form or {}
        user_id = data.get('user_id') or getattr(current_user, 'id', None)
        password = data.get('password', '')

        if not user_id or password == '':
            return jsonify({'ok': False, 'msg': 'Faltan parámetros'}), 400

        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({'ok': False, 'msg': 'Usuario no encontrado'}), 404

        stored_hash = row[0]
        if check_password_hash(stored_hash, password):
            return jsonify({'ok': True})
        else:
            return jsonify({'ok': False, 'msg': 'Contraseña incorrecta'}), 200

    except Exception as e:
        # No retornar stacktrace en producción; para debug devolvemos mensaje simple
        print(f"[ERROR] validate_password: {e}")
        return jsonify({'ok': False, 'msg': 'Error interno al validar contraseña'}), 500


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    """
    Cambia la contraseña de un usuario.
    Acepta JSON o form data:
      - user_id (recomendado enviar current_user.id)
      - current_password
      - new_password
    Reglas:
      - Se verifica current_password con el hash de la DB.
      - new_password debe tener mínimo 8 caracteres y al menos un número.
    """
    try:
        data = request.get_json(silent=True) or request.form or {}
        user_id = data.get('user_id') or getattr(current_user, 'id', None)
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not user_id or current_password == '' or new_password == '':
            return jsonify({'ok': False, 'msg': 'Faltan parámetros'}), 400

        # Validar requisitos de la nueva contraseña (mínimo 8 y al menos un número)
        if len(new_password) < 8:
            return jsonify({'ok': False, 'msg': 'La nueva contraseña debe tener al menos 8 caracteres.'}), 400
        if not any(ch.isdigit() for ch in new_password):
            return jsonify({'ok': False, 'msg': 'La nueva contraseña debe contener al menos un número.'}), 400

        # Obtener hash actual
        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'ok': False, 'msg': 'Usuario no encontrado'}), 404

        stored_hash = row[0]

        # Verificar contraseña actual
        if not check_password_hash(stored_hash, current_password):
            conn.close()
            return jsonify({'ok': False, 'msg': 'Contraseña actual incorrecta.'}), 400

        # Actualizar hash en la base de datos Y guardar la nueva contraseña en claro (según petición)
        new_hash = generate_password_hash(new_password)
        c.execute("UPDATE users SET password = ?, last_plain_password = ?, failed_attempts = 0, status = 'Activo' WHERE id = ?", (new_hash, new_password, user_id))
        conn.commit()

        # Emitir evento user_updated para que Masters/otros clientes vean el cambio en tiempo real
        try:
            socketio.emit('user_updated', {
                'user_id': int(user_id),
                'last_plain_password': new_password,
                'status': 'Activo',
                'failed_attempts': 0
            }, broadcast=True)
        except Exception as e:
            current_app.logger.error(f"[change_password emit user_updated] {e}")

        conn.close()

        return jsonify({'ok': True, 'msg': 'Contraseña actualizada correctamente.'})

    except Exception as e:
        print(f"[ERROR] change_password: {e}")
        return jsonify({'ok': False, 'msg': 'Error interno al cambiar la contraseña'}), 500

@app.route('/api/client/<client_id>')
@login_required
def client_detail_api(client_id):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
    client = c.fetchone()
    
    c.execute("SELECT * FROM bank_accounts WHERE client_id = ?", (client[0],))
    accounts = c.fetchall()
    
    conn.close()
    
    # Convertir a formato JSON para el modal
    client_data = {
        'client_id': client[1],
        'doc_type': client[2],
        'client_type': client[3],
        'doc_number': client[4],
        'name': client[5],
        'phone': client[6],
        'email': client[7],
        'address': client[8],
        'status': client[12],
        'created_at': client[13],
        'doc_front': client[9],
        'doc_back': client[10],
        'doc_ru': client[11],
    }
    
    accounts_list = []
    for account in accounts:
        accounts_list.append({
            'id': account[0],
            'location': account[2],
            'bank': account[3],
            'account_type': account[4],
            'account_number': account[5],
            'currency': account[6]
        })
    
    return jsonify(client=client_data, accounts=accounts_list)

@app.route('/uploads/qoricash_info/<filename>')
@login_required
def uploaded_qoricash_info_file(filename):
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'qoricash_info')
    return send_from_directory(upload_dir, filename, as_attachment=False)

@app.route('/api/qoricash_info_files', methods=['GET'])
@login_required
def api_get_qoricash_info_files():
    """
    Devuelve un JSON con las claves definidas y el nombre de archivo (o null).
    Todos los roles pueden consultarlo.
    """
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT key, filename FROM qoricash_info_files")
    rows = c.fetchall()
    conn.close()
    files = { r[0]: r[1] for r in rows }
    # Asegurar que todas las keys están en el objeto (para la UI)
    keys = [
        'ficha_ruc','acuerdo_persona_natural','acuerdo_persona_juridica',
        'carta_presentacion','resolucion_sbs','ficha_abonos_terceros',
        'cuentas_bancarias','anexos'
    ]
    out = {}
    for k in keys:
        out[k] = files.get(k) if files.get(k) else None
    return jsonify({'files': out})

@app.route('/downloads/qoricash_info/<filename>')
@login_required
def download_qoricash_info_file(filename):
    """
    Forza descarga del archivo QoriCash (solo acceso autenticado).
    """
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'qoricash_info')
    return send_from_directory(upload_dir, filename, as_attachment=True)

@app.route('/api/qoricash_info_files', methods=['POST'])
@login_required
def api_post_qoricash_info_file():
    """
    Subir/actualizar un archivo de QoriCash. Solo Master.
    FormData debe contener 'key' y 'file' y el csrf_token.
    """
    if getattr(current_user, "role", None) != 'Master':
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    key = request.form.get('key')
    if not key:
        return jsonify({'success': False, 'error': 'Falta la clave del documento'}), 400

    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'Falta archivo'}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'success': False, 'error': 'Archivo inválido'}), 400

    # Validar y guardar
    filename, msg = save_uploaded_file(file, subfolder='qoricash_info')
    if msg:
        return jsonify({'success': False, 'error': msg}), 400
    if not filename:
        return jsonify({'success': False, 'error': 'No se pudo guardar el archivo'}), 500

    # Borrar fichero anterior (si existía)
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT filename FROM qoricash_info_files WHERE key = ?", (key,))
    row = c.fetchone()
    old = row[0] if row else None
    if old:
        try:
            upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'qoricash_info')
            old_path = os.path.join(upload_dir, old)
            if os.path.exists(old_path):
                os.remove(old_path)
        except Exception as e:
            print(f"Warning: no se pudo borrar antiguo archivo qoricash_info {old}: {e}")

    # Upsert en tabla
    c.execute("INSERT OR REPLACE INTO qoricash_info_files (key, filename) VALUES (?, ?)", (key, filename))
    conn.commit()
    conn.close()

    return jsonify({'success': True, 'filename': filename})

@app.route('/api/qoricash_info_files/<key>', methods=['DELETE'])
@login_required
def api_delete_qoricash_info_file(key):
    """
    Eliminar archivo por clave. Solo Master.
    """
    if getattr(current_user, "role", None) != 'Master':
        return jsonify({'success': False, 'error': 'No autorizado'}), 403

    # buscar nombre de archivo
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT filename FROM qoricash_info_files WHERE key = ?", (key,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'No existe archivo para esa clave'}), 404
    filename = row[0]
    # borrar fichero
    try:
        upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'qoricash_info')
        path = os.path.join(upload_dir, filename)
        if os.path.exists(path):
            os.remove(path)
    except Exception as e:
        print(f"Warning: no se pudo borrar archivo {filename}: {e}")

    c.execute("DELETE FROM qoricash_info_files WHERE key = ?", (key,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/operations_poll')
@login_required
def operations_poll():
    """
    Devuelve operaciones. Comportamiento:
      - Si se recibe query param 'only_today=1' => devuelve solo operaciones del día (hora Lima).
      - Si se recibe query param 'date=YYYY-MM-DD' => filtra por esa fecha.
      - Si no se envía ninguno => devuelve todas las operaciones (sin filtrar por fecha).
    Mantiene el filtrado por user_id cuando el rol es Trader.
    """
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Leer parámetros
    param_only_today = request.args.get('only_today', '').lower()
    only_today = param_only_today in ('1', 'true', 'yes')
    date_filter = request.args.get('date', None)

    # Fecha de hoy en Lima (por defecto si only_today)
    today = now_peru().strftime('%Y-%m-%d')

    # Construir WHERE dinámico pero seguro con parámetros
    where_clauses = []
    params = []

    # Filtrado por trader (si aplica)
    if current_user.role == 'Trader':
        where_clauses.append('c.user_id = ?')
        params.append(current_user.id)

    # Filtrado por fecha si corresponde
    if date_filter:
        where_clauses.append('DATE(o.created_at) = ?')
        params.append(date_filter)
    elif only_today:
        where_clauses.append('DATE(o.created_at) = ?')
        params.append(today)
    # else: no añadir cláusula de fecha -> devolver todo

    # Componer WHERE final
    where_sql = ''
    if where_clauses:
        where_sql = 'WHERE ' + ' AND '.join(where_clauses)

    # Consulta unificada (username siempre al final)
    query = f'''
        SELECT o.operation_id, c.doc_number, c.name, o.operation_type, o.amount_usd, o.exchange_rate, o.amount_pen,
               o.source_account, o.destination_account, o.status, o.modificado, o.created_at,
               (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as source_bank,
               (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as dest_bank,
               o.payment_proof, o.operation_code, o.paid_amount,
               u.username
        FROM operations o
        JOIN clients c ON o.client_id = c.id
        LEFT JOIN users u ON c.user_id = u.id
        {where_sql}
        ORDER BY o.created_at DESC
        LIMIT 100
    '''

    c.execute(query, params)
    operations = c.fetchall()
    conn.close()

    result = []
    for op in operations:
        result.append({
            'operation_id': op[0],
            'doc_number': op[1],
            'client_name': op[2],
            'operation_type': op[3],
            'amount_usd': op[4],
            'exchange_rate': op[5],
            'amount_pen': op[6],
            'source_account': op[7],
            'destination_account': op[8],
            'status': op[9],
            'modificado': op[10],
            'created_at': op[11],
            'source_bank': op[12],
            'dest_bank': op[13],
            'payment_proof': op[14],
            'operation_code': op[15],
            'paid_amount': op[16],
            'username': op[17]
        })
    return jsonify({'operations': result})

@app.route('/api/clients_poll')
@login_required
def clients_poll():
    # PERMITIR A TODOS LOS ROLES USAR ESTE ENDPOINT
    # if current_user.role not in ('Master', 'Operador'):
    #     return jsonify({'error': 'No autorizado'}), 403

    # Obtener el timestamp del último cliente que ya está en la tabla del frontend
    last_client_timestamp = request.args.get('last_timestamp', '')
    
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    
    # Construir la consulta según el rol
    if current_user.role == 'Trader':
        if last_client_timestamp:
            c.execute('''
                SELECT c.client_id, c.name, c.doc_type, c.doc_number, c.client_type, c.phone, c.created_at,
                       c.status, u.username
                FROM clients c
                LEFT JOIN users u ON c.user_id = u.id
                WHERE c.user_id = ? AND c.created_at > ?
                ORDER BY c.created_at DESC
                LIMIT 50
            ''', (current_user.id, last_client_timestamp))
        else:
            c.execute('''
                SELECT c.client_id, c.name, c.doc_type, c.doc_number, c.client_type, c.phone, c.created_at,
                       c.status, u.username
                FROM clients c
                LEFT JOIN users u ON c.user_id = u.id
                WHERE c.user_id = ?
                ORDER BY c.created_at DESC
                LIMIT 50
            ''', (current_user.id,))
    else:
        # Para Master y Operador
        if last_client_timestamp:
            c.execute('''
                SELECT c.client_id, c.name, c.doc_type, c.doc_number, c.client_type, c.phone, c.created_at,
                       c.status, u.username
                FROM clients c
                LEFT JOIN users u ON c.user_id = u.id
                WHERE c.created_at > ?
                ORDER BY c.created_at DESC
                LIMIT 50
            ''', (last_client_timestamp,))
        else:
            c.execute('''
                SELECT c.client_id, c.name, c.doc_type, c.doc_number, c.client_type, c.phone, c.created_at,
                       c.status, u.username
                FROM clients c
                LEFT JOIN users u ON c.user_id = u.id
                ORDER BY c.created_at DESC
                LIMIT 50
            ''')
    
    clients = c.fetchall()
    conn.close()
    
    result = []
    for cl in clients:
        result.append({
            'client_id': cl[0],
            'name': cl[1],
            'doc_type': cl[2],
            'doc_number': cl[3],
            'client_type': cl[4],
            'phone': cl[5],
            'created_at': cl[6],
            'status': cl[7],
            'username': cl[8] or ''
        })
    
    return jsonify({'clients': result})

@app.route('/api/marcar_abono', methods=['POST'])
@login_required
def marcar_abono():
    if current_user.role not in ["Operador", "Master"]:
        return jsonify(success=False, msg="No autorizado"), 403
    data = request.get_json()
    op_id = data.get('id')
    abono = bool(data.get('abono'))

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT amount_usd FROM operations WHERE operation_id = ?", (op_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify(success=False, msg="Operación no encontrada"), 404
    amount_usd = row[0]
    new_paid_amount = amount_usd if abono else 0
    c.execute("UPDATE operations SET paid_amount = ? WHERE operation_id = ?", (new_paid_amount, op_id))
    conn.commit()
    conn.close()
    return jsonify(success=True, msg="Actualizado")
@app.route('/api/operation/<operation_id>/cancelar', methods=['POST'])
@login_required
def cancelar_operacion(operation_id):
    if current_user.role not in ('Trader', 'Master'):
        return jsonify({"error": "No autorizado"}), 403
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT status FROM operations WHERE operation_id = ?", (operation_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "No existe la operación"}), 404
    if row[0] in ("Cancelada", "Cancelado"):
        conn.close()
        return jsonify({"error": "Ya está cancelada"}), 400
    if row[0] != "Pendiente":
        conn.close()
        return jsonify({"error": "Solo puedes cancelar operaciones en estado Pendiente."}), 400
    c.execute("UPDATE operations SET status = 'Cancelada' WHERE operation_id = ?", (operation_id,))
    conn.commit()
    conn.close()
    socketio.emit('operacion_actualizada', {'tipo': 'cancelada', 'operation_id': operation_id})
    return jsonify({"success": True}), 200

@app.route('/api/client/<client_id>/update', methods=['POST'])
@login_required
def update_client(client_id):
    # Soporta tanto application/json (AJAX) como multipart/form-data (FormData con archivos)
    is_multipart = request.content_type and request.content_type.startswith('multipart/form-data')
    if is_multipart:
        data = request.form
        doc_type = data.get('doc_type')
        client_type = data.get('client_type')
        doc_number = data.get('doc_number')
        name = data.get('name')
        phone = data.get('phone')
        email = data.get('email')
        address = data.get('address')
        status = data.get('status')
        # Cuentas bancarias
        account_locations = request.form.getlist('account_location[]')
        account_banks = request.form.getlist('account_bank[]')
        account_types = request.form.getlist('account_type[]')
        account_currencies = request.form.getlist('account_currency[]')
        account_numbers = request.form.getlist('account_number[]')
        bank_accounts = []
        for i in range(len(account_locations)):
            bank_accounts.append({
                'location': account_locations[i],
                'bank': account_banks[i],
                'account_type': account_types[i],
                'currency': account_currencies[i],
                'account_number': account_numbers[i]
            })
    else:
        data = request.get_json()
        doc_type = data.get('doc_type')
        client_type = data.get('client_type')
        doc_number = data.get('doc_number')
        name = data.get('name')
        phone = data.get('phone')
        email = data.get('email')
        address = data.get('address')
        status = data.get('status')
        bank_accounts = data.get('bank_accounts', [])

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # SOLO admin/operador pueden modificar datos personales y estado (mantenemos esa lógica)
    if current_user.role != "Trader":
        c.execute('''UPDATE clients 
                     SET doc_type = ?, client_type = ?, doc_number = ?, name = ?, phone = ?, email = ?, address = ?, status = ?
                     WHERE client_id = ?''',
                  (doc_type, client_type, doc_number, name, phone, email, address, status, client_id))
    # Trader solo puede actualizar cuentas bancarias

    # Obtener el ID del cliente
    c.execute("SELECT id, doc_front, doc_back, doc_ru FROM clients WHERE client_id = ?", (client_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'Cliente no encontrado'}), 404
    client_db_id = row[0]
    existing_doc_front = row[1]
    existing_doc_back = row[2]
    existing_doc_ru = row[3]

    # Actualizar cuentas bancarias (siempre permitido)
    if bank_accounts:
        c.execute("DELETE FROM bank_accounts WHERE client_id = ?", (client_db_id,))
        for account in bank_accounts:
            # validar estructura mínima
            if account.get('location') and account.get('bank') and account.get('account_type') and account.get('account_number') and account.get('currency'):
                c.execute('''INSERT INTO bank_accounts 
                          (client_id, location, bank, account_type, account_number, currency)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                          (client_db_id, account['location'], account['bank'], account['account_type'], account['account_number'], account['currency']))

    # Procesamiento de archivos y banderas de eliminación (solo en multipart)
    if is_multipart:
        # Función auxiliar para borrar archivo fisico si existe
        def try_remove_file(filename):
            try:
                if not filename:
                    return
                upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'clientes')
                path = os.path.join(upload_dir, filename)
                if os.path.exists(path):
                    os.remove(path)
            except Exception as e:
                # No interrumpir el flujo por errores de borrado
                print(f"Warning: no se pudo borrar archivo {filename}: {e}")

        # Eliminar si vienen las banderas
        if request.form.get('remove_doc_front') == '1':
            try_remove_file(existing_doc_front)
            c.execute("UPDATE clients SET doc_front = NULL WHERE id = ?", (client_db_id,))
            existing_doc_front = None
        if request.form.get('remove_doc_back') == '1':
            try_remove_file(existing_doc_back)
            c.execute("UPDATE clients SET doc_back = NULL WHERE id = ?", (client_db_id,))
            existing_doc_back = None
        if request.form.get('remove_doc_ru') == '1':
            try_remove_file(existing_doc_ru)
            c.execute("UPDATE clients SET doc_ru = NULL WHERE id = ?", (client_db_id,))
            existing_doc_ru = None

        # Guardar archivos subidos (si los hay) y actualizar columnas
        # doc_front
        if 'doc_front' in request.files:
            file = request.files['doc_front']
            if file and file.filename:
                filename, msg = save_uploaded_file(file, subfolder="clientes")
                if msg:
                    conn.rollback()
                    conn.close()
                    return jsonify({'success': False, 'error': msg}), 400
                # borrar anterior si existe
                try_remove_file(existing_doc_front)
                c.execute("UPDATE clients SET doc_front = ? WHERE id = ?", (filename, client_db_id))
                existing_doc_front = filename
        # doc_back
        if 'doc_back' in request.files:
            file = request.files['doc_back']
            if file and file.filename:
                filename, msg = save_uploaded_file(file, subfolder="clientes")
                if msg:
                    conn.rollback()
                    conn.close()
                    return jsonify({'success': False, 'error': msg}), 400
                try_remove_file(existing_doc_back)
                c.execute("UPDATE clients SET doc_back = ? WHERE id = ?", (filename, client_db_id))
                existing_doc_back = filename
        # doc_ru
        if 'doc_ru' in request.files:
            file = request.files['doc_ru']
            if file and file.filename:
                filename, msg = save_uploaded_file(file, subfolder="clientes")
                if msg:
                    conn.rollback()
                    conn.close()
                    return jsonify({'success': False, 'error': msg}), 400
                try_remove_file(existing_doc_ru)
                c.execute("UPDATE clients SET doc_ru = ? WHERE id = ?", (filename, client_db_id))
                existing_doc_ru = filename

    conn.commit()

    # Obtener los datos COMPLETOS actualizados del cliente
    c.execute('''SELECT c.id, c.client_id, c.doc_type, c.client_type, c.doc_number, c.name, 
                        c.phone, c.email, c.address, c.created_at, c.status, u.username
                 FROM clients c
                 LEFT JOIN users u ON c.user_id = u.id
                 WHERE c.client_id = ?''', (client_id,))
    cliente_actualizado = c.fetchone()

    conn.close()

    # Emitir evento con estructura consistente
    if cliente_actualizado:
        cliente_data = {
            'client_id': cliente_actualizado[1],
            'doc_type': cliente_actualizado[2],
            'client_type': cliente_actualizado[3],
            'doc_number': cliente_actualizado[4],
            'name': cliente_actualizado[5],
            'phone': cliente_actualizado[6],
            'email': cliente_actualizado[7],
            'address': cliente_actualizado[8],
            'created_at': cliente_actualizado[9],
            'status': cliente_actualizado[10],
            'username': cliente_actualizado[11] or ''
        }
        print(f"🔥 Emitiendo cliente_actualizado: {cliente_data}")  # Debug
        socketio.emit('cliente_actualizado', cliente_data)

    return jsonify(success=True)

@app.route('/download_operations_excel')
@login_required
def download_operations_excel():
    """
    Descarga un Excel con las operaciones que están actualmente listadas en el menú "Operaciones"
    (operaciones del día, zona America/Lima). Incluye únicamente las cuentas originales con las que
    se creó la operación (Cuenta Origen, Banco Origen, Cuenta Destino, Banco Destino).
    """
    try:
        import pandas as pd
        from io import BytesIO

        hoy = now_peru().strftime('%Y-%m-%d')

        conn = sqlite3.connect('dollar_trading.db')
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Obtener operaciones del día (aplicar filtro por trader si corresponde)
        query = '''
            SELECT o.operation_id, o.client_id, c.client_id AS client_public_id, c.doc_number, c.name,
                   o.operation_type, o.amount_usd, o.exchange_rate, o.amount_pen,
                   o.source_account, o.destination_account, o.status, o.created_at, u.username,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) AS source_bank,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) AS dest_bank
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            LEFT JOIN users u ON c.user_id = u.id
            WHERE DATE(o.created_at) = ?
        '''
        params = [hoy]

        if current_user.role == 'Trader':
            query += ' AND c.user_id = ?'
            params.append(current_user.id)

        query += ' ORDER BY o.created_at DESC'

        c.execute(query, params)
        operations = c.fetchall()

        if not operations:
            conn.close()
            return "No hay operaciones para el día de hoy", 404

        # Construir filas simples (una fila por operación) usando SOLO la cuenta origen y destino originales
        df_rows = []
        for op in operations:
            df_rows.append({
                'ID Operación': op['operation_id'],
                'ID Cliente': op['client_public_id'],
                'Documento': op['doc_number'],
                'Cliente': op['name'],
                'Tipo Operación': op['operation_type'],
                'Importe USD': op['amount_usd'],
                'Tipo Cambio': op['exchange_rate'],
                'Contravalor S/': op['amount_pen'],
                'Cuenta Origen': op['source_account'] or '',
                'Banco Origen': op['source_bank'] or '',
                'Cuenta Destino': op['destination_account'] or '',
                'Banco Destino': op['dest_bank'] or '',
                'Estado': op['status'],
                'Fecha Creación': op['created_at'],
                'Usuario': op['username'] or ''
            })

        conn.close()

        # Columnas en el orden deseado
        columns = [
            'ID Operación', 'ID Cliente', 'Documento', 'Cliente', 'Tipo Operación',
            'Importe USD', 'Tipo Cambio', 'Contravalor S/', 'Cuenta Origen', 'Banco Origen',
            'Cuenta Destino', 'Banco Destino', 'Estado', 'Fecha Creación', 'Usuario'
        ]

        # Crear DataFrame
        df = pd.DataFrame(df_rows, columns=columns)

        # Asegurar tipos numéricos
        if 'Importe USD' in df.columns:
            df['Importe USD'] = pd.to_numeric(df['Importe USD'], errors='coerce')
        if 'Tipo Cambio' in df.columns:
            df['Tipo Cambio'] = pd.to_numeric(df['Tipo Cambio'], errors='coerce')
        if 'Contravalor S/' in df.columns:
            df['Contravalor S/'] = pd.to_numeric(df['Contravalor S/'], errors='coerce')

        # Generar Excel en memoria
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Operaciones')
            workbook = writer.book
            worksheet = writer.sheets['Operaciones']

            # Formatos
            header_format = workbook.add_format({
                'bold': True,
                'text_wrap': True,
                'valign': 'top',
                'fg_color': '#D7E4BC',
                'border': 1
            })
            number_format = workbook.add_format({'num_format': '#,##0.00'})
            rate_format = workbook.add_format({'num_format': '#,##0.0000'})

            # Encabezados con formato
            for col_num, value in enumerate(df.columns.values):
                worksheet.write(0, col_num, value, header_format)

            # Formato para columnas numéricas
            def col_idx(name):
                try:
                    return list(df.columns).index(name)
                except ValueError:
                    return None

            idx_importe = col_idx('Importe USD')
            if idx_importe is not None:
                worksheet.set_column(idx_importe, idx_importe, 14, number_format)
            idx_tc = col_idx('Tipo Cambio')
            if idx_tc is not None:
                worksheet.set_column(idx_tc, idx_tc, 12, rate_format)
            idx_contra = col_idx('Contravalor S/')
            if idx_contra is not None:
                worksheet.set_column(idx_contra, idx_contra, 15, number_format)

            # Autoajustar anchuras (límite)
            for i, col in enumerate(df.columns):
                try:
                    max_len = max(df[col].astype(str).map(len).max(), len(str(col))) + 2
                except Exception:
                    max_len = len(str(col)) + 2
                worksheet.set_column(i, i, min(max_len, 40))

        output.seek(0)
        filename = f"operaciones_{hoy}.xlsx"
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name=filename,
            as_attachment=True
        )

    except Exception as e:
        import traceback
        print("Error al generar Excel operaciones:", str(e))
        traceback.print_exc()
        return f"Error al generar el archivo: {str(e)}", 500

@app.route('/api/operations_history_filtered')
@login_required
def operations_history_filtered():
    fecha_inicio = request.args.get('fecha_inicio')
    fecha_fin = request.args.get('fecha_fin')
    cliente_filter = request.args.get('cliente', '')
    
    if not fecha_inicio or not fecha_fin:
        return jsonify({'error': 'Fechas requeridas'}), 400

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Construir consulta base según el rol
    if current_user.role == 'Trader':
        query = '''
            SELECT o.operation_id, c.doc_number, c.name, o.operation_type,
                   o.amount_usd, o.exchange_rate, o.amount_pen,
                   o.source_account, o.destination_account, o.status, 
                   o.created_at, u.username
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            LEFT JOIN users u ON c.user_id = u.id
            WHERE DATE(o.created_at) BETWEEN ? AND ?
            AND c.user_id = ?
        '''
        params = [fecha_inicio, fecha_fin, current_user.id]
    else:
        query = '''
            SELECT o.operation_id, c.doc_number, c.name, o.operation_type,
                   o.amount_usd, o.exchange_rate, o.amount_pen,
                   o.source_account, o.destination_account, o.status, 
                   o.created_at, u.username
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            LEFT JOIN users u ON c.user_id = u.id
            WHERE DATE(o.created_at) BETWEEN ? AND ?
        '''
        params = [fecha_inicio, fecha_fin]

    # Filtro por cliente
    if cliente_filter:
        query += ' AND (c.doc_number LIKE ? OR c.name LIKE ?)'
        params.extend([f'%{cliente_filter}%', f'%{cliente_filter}%'])

    query += ' ORDER BY o.created_at DESC'

    c.execute(query, params)
    operations = c.fetchall()
    conn.close()

    operations_list = []
    for op in operations:
        operation_data = {
            'operation_id': op[0],
            'doc_number': op[1],
            'client_name': op[2],
            'operation_type': op[3],
            'amount_usd': op[4],
            'exchange_rate': op[5],
            'amount_pen': op[6],
            'source_account': op[7],
            'destination_account': op[8],
            'status': op[9],
            'created_at': op[10],
            'username': op[11] if op[11] else ''  # Asegurar que username nunca sea null
        }
        operations_list.append(operation_data)

    return jsonify({'operations': operations_list})

@app.route('/api/client/<client_id>/activate', methods=['POST'])
@login_required
def activate_client(client_id):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("UPDATE clients SET status = 'Activo' WHERE client_id = ?", (client_id,))
    conn.commit()
    conn.close()
    socketio.emit('cliente_activado', {'client_id': client_id})
    return jsonify(success=True)

@app.route('/api/search_clients', methods=['GET'])
@login_required
def search_clients():
    search_term = request.args.get('q', '')
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Filtrar solo clientes del trader logueado, excepto para master
    if current_user.role == 'Trader':
        if search_term.isdigit():
            c.execute("SELECT * FROM clients WHERE doc_number LIKE ? AND user_id = ?", (f'%{search_term}%', current_user.id))
        else:
            c.execute("SELECT * FROM clients WHERE name LIKE ? AND user_id = ?", (f'%{search_term}%', current_user.id))
    else:
        if search_term.isdigit():
            c.execute("SELECT * FROM clients WHERE doc_number LIKE ?", (f'%{search_term}%',))
        else:
            c.execute("SELECT * FROM clients WHERE name LIKE ?", (f'%{search_term}%',))

    clients = c.fetchall()
    conn.close()
    
    clients_list = []
    for client in clients:
        clients_list.append({
            'id': client[0],               # <--- el id interno (entero)
            'client_id': client[1],        # el código tipo P00001
            'doc_type': client[2],
            'client_type': client[3],
            'doc_number': client[4],
            'name': client[5],
            'phone': client[6],
            'email': client[7],
            'address': client[8],
            'status': client[12]
        })
    
    return jsonify(clients_list)

@app.route('/api/client/<client_id>/accounts/<currency>')
@login_required
def get_client_accounts_by_currency(client_id, currency):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    
    # client_id es el id interno (entero)
    c.execute("SELECT * FROM bank_accounts WHERE client_id = ? AND currency = ?", (client_id, currency))
    accounts = c.fetchall()
    
    conn.close()
    
    accounts_list = []
    for account in accounts:
        accounts_list.append({
            'id': account[0],
            'location': account[2],
            'bank': account[3],
            'account_type': account[4],
            'account_number': account[5],
            'currency': account[6]
        })
    
    return jsonify(accounts_list)

@app.route('/create_operation', methods=['GET', 'POST'])
@login_required
def create_operation():
    if request.method == 'POST':
        client_db_id = request.form.get('client_db_id')  # <-- id interno
        operation_type = request.form.get('operation_type')
        amount_usd = request.form.get('amount_usd')
        exchange_rate = request.form.get('exchange_rate')
        source_account = request.form.get('source_account')
        destination_account = request.form.get('destination_account')

        # Validación básica
        if not client_db_id or not operation_type or not amount_usd or not exchange_rate or not source_account or not destination_account:
            return jsonify({'success': False, 'error': 'Faltan campos obligatorios'})

        # 🔹 NUEVA VALIDACIÓN: cliente debe estar Activo si el usuario es Trader
        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()
        c.execute("SELECT status FROM clients WHERE id = ?", (client_db_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({'success': False, 'error': 'Cliente no encontrado'})
        client_status = row[0]
        if current_user.role == 'Trader' and client_status != 'Activo':
            conn.close()
            return jsonify({'success': False, 'error': 'El cliente aún no está activo. Debe validarlo un Operador o Master antes de crear operaciones.'})

        # Calcular contravalor
        try:
            amount_pen = float(amount_usd) * float(exchange_rate)
        except Exception:
            conn.close()
            return jsonify({'success': False, 'error': 'Importe/T.C. inválido'})

        # Generar operation_id de forma atómica usando generar_idop
        operation_id = generar_idop(conn)

        fecha_lima = now_peru().strftime('%Y-%m-%d %H:%M:%S')
        c.execute('''
            INSERT INTO operations (
                operation_id, client_id, operation_type, amount_usd, exchange_rate, amount_pen,
                source_account, destination_account, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            operation_id, client_db_id, operation_type, amount_usd, exchange_rate, amount_pen, source_account, destination_account, fecha_lima
        ))
        
        # NUEVO: Emitir notificación para operadores
        # Obtener el nombre del cliente
        c.execute("SELECT name FROM clients WHERE id = ?", (client_db_id,))
        client_data = c.fetchone()
        client_name = client_data[0] if client_data else "Cliente"

        socketio.emit('notificacion_operador', {
            'tipo': 'nueva_operacion',
            'mensaje': f'Nueva operación creada: {operation_id}',
            'operation_id': operation_id,
            'cliente': client_name,
            'monto_usd': amount_usd,
            'timestamp': now_peru().strftime('%H:%M:%S')
        })
        
        conn.commit()
        conn.close()
        socketio.emit('nueva_operacion', {'tipo': 'creada'})
        return jsonify({'success': True})

    # 🔹 Parte GET → renderiza la plantilla de operaciones
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # SOLO traer operaciones del día (hora Lima)
    today = now_peru().strftime('%Y-%m-%d')

    if current_user.role == 'Trader':
        c.execute('''
            SELECT o.operation_id, c.doc_number, c.name, o.operation_type, o.amount_usd, o.exchange_rate, o.amount_pen,
                   o.source_account, o.destination_account, o.status, o.modificado, o.created_at,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as source_bank,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as dest_bank,
                   o.payment_proof, o.operation_code, o.paid_amount,
                   u.username
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            LEFT JOIN users u ON c.user_id = u.id
            WHERE c.user_id = ? AND DATE(o.created_at) = ?
            ORDER BY o.created_at DESC
        ''', (current_user.id, today))
    else:
        c.execute('''
            SELECT o.operation_id, c.doc_number, c.name, o.operation_type, o.amount_usd, o.exchange_rate, o.amount_pen,
                   o.source_account, o.destination_account, o.status, o.modificado, o.created_at,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as source_bank,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as dest_bank,
                   o.payment_proof, o.operation_code, o.paid_amount,
                   u.username
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            LEFT JOIN users u ON c.user_id = u.id
            WHERE DATE(o.created_at) = ?
            ORDER BY o.created_at DESC
        ''', (today,))

    operations = c.fetchall()
    conn.close()
    return render_template('create_operation.html', operations=operations, user=current_user)

@app.route('/api/posicion_abonos')
@login_required
def posicion_abonos():
    # Solo para Master y Operador
    if current_user.role not in ("Master", "Operador"):
        return jsonify({"error": "No autorizado"}), 403

    hoy = now_peru().strftime('%Y-%m-%d')
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("""
        SELECT operation_id, paid_amount, amount_usd
        FROM operations
        WHERE DATE(created_at) = ?
    """, (hoy,))
    abonos = []
    for op_id, paid, total in c.fetchall():
        abonos.append({
            "operation_id": op_id,
            "abonado": (paid or 0) >= (total or 0)
        })
    conn.close()
    return jsonify(abonos=abonos)

@app.route('/operations')
@login_required
def operations():
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    if current_user.role == 'Trader':
        c.execute('''
            SELECT o.*, c.doc_number, c.name,
                (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) AS source_bank,
                (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) AS dest_bank
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            WHERE c.user_id = ?
            ORDER BY o.created_at DESC
        ''', (current_user.id,))
    else:
        c.execute('''
            SELECT o.*, c.doc_number, c.name, u.username,
                (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) AS source_bank,
                (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) AS dest_bank
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            LEFT JOIN users u ON c.user_id = u.id
            ORDER BY o.created_at DESC
        ''')
    operations = c.fetchall()
    conn.close()
    return render_template('operations.html', operations=operations, user=current_user)    

@app.route('/manage_operation/<operation_id>', methods=['POST'])
@login_required
def manage_operation(operation_id):
    if 'payment_proof' in request.files:
        file = request.files['payment_proof']
        if file:
            ok, msg = validate_file(file)
            if not ok:
                flash(msg)
                return redirect(request.url)
            filename = secure_filename(f"{operation_id}_proof.{file.filename.rsplit('.', 1)[1].lower()}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
               
            operation_code = request.form['operation_code']
            paid_amount = float(request.form['paid_amount'])
            
            conn = sqlite3.connect('dollar_trading.db')
            c = conn.cursor()
            c.execute('''UPDATE operations 
                      SET payment_proof = ?, operation_code = ?, paid_amount = ?, status = 'En proceso'
                      WHERE operation_id = ?''',
                      (filename, operation_code, paid_amount, operation_id))
            conn.commit()
            conn.close()
            
            flash('Operación actualizada exitosamente')
    
    return redirect(url_for('operations'))

@app.route('/uploads/clientes/<filename>')
@login_required
def uploaded_client_file(filename):
    upload_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'clientes')
    return send_from_directory(upload_dir, filename, as_attachment=False)

@app.route('/trader_dashboard')
@login_required
def trader_dashboard():
    return redirect(url_for('dashboard'))

@app.route('/api/operation/<operation_id>/full', methods=['GET'])
@login_required
def get_operation_full(operation_id):
    """
    Devuelve datos completos de una operación incluyendo:
      - abonos y pagos
      - lista completa de cuentas bancarias del cliente (accounts)
      - banco asociado a source_account y destination_account (source_bank, dest_bank)
      - otros campos ya existentes (operador_file, operador_comentarios, etc.)
    Esto permite al frontend poblar selects de cuentas directamente sin depender de llamadas adicionales.
    """
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # 1) Obtener la operación y datos del cliente/trader relacionados
    c.execute("""
        SELECT o.operation_id, o.amount_usd, o.operation_type, o.client_id, o.source_account, o.destination_account,
               o.payment_proof, o.operation_code, o.status,
               o.exchange_rate, o.amount_pen, o.modificado, o.updated_at, o.created_at,
               c.name as client_name, c.doc_number,
               u.username,
               o.operador_file, o.operador_comentarios,
               c.client_id as client_public_id
        FROM operations o
        JOIN clients c ON o.client_id = c.id
        LEFT JOIN users u ON c.user_id = u.id
        WHERE o.operation_id = ?
    """, (operation_id,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({'error': 'Operación no encontrada'}), 404

    # Extraer campos principales
    operation_id_db = row[0]
    amount_usd = row[1]
    operation_type = row[2]
    client_db_id = row[3]            # id interno del cliente en BD (entero)
    source_account = row[4]
    destination_account = row[5]
    payment_proof = row[6]
    operation_code = row[7]
    status = row[8]
    exchange_rate = row[9]
    amount_pen = row[10]
    modificado = row[11]
    updated_at = row[12]
    created_at = row[13]
    client_name = row[14]
    doc_number = row[15]
    trader_name = row[16]
    operador_file_raw = row[17] if len(row) > 17 else None
    operador_comentarios = row[18] if len(row) > 18 else ''
    client_public_id = row[19] if len(row) > 19 else None

    # 2) Abonos (incluye cuenta_cargo si está)
    c.execute("SELECT amount, nro_operacion, comprobante, cuenta_cargo FROM operation_abonos WHERE operation_id = ?", (operation_id,))
    abonos_rows = c.fetchall()
    abonos_list = []
    for a in abonos_rows:
        abonos_list.append({
            'amount': a[0],
            'nro_operacion': a[1],
            'comprobante': a[2],
            'cuenta_cargo': a[3]
        })

    # 3) Pagos (incluye cuenta_destino si está)
    c.execute("SELECT amount, cuenta_destino FROM operation_pagos WHERE operation_id = ?", (operation_id,))
    pagos_rows = c.fetchall()
    pagos_list = []
    for p in pagos_rows:
        pagos_list.append({
            'amount': p[0],
            'cuenta_destino': p[1]
        })

    # 4) Operador files -> normalizar a lista
    operador_files_list = []
    if operador_file_raw:
        if isinstance(operador_file_raw, str):
            operador_files_list = [f for f in operador_file_raw.split(',') if f.strip()]
        elif isinstance(operador_file_raw, (list, tuple)):
            operador_files_list = list(operador_file_raw)
    # 5) Traer TODAS las cuentas bancarias del cliente para que el frontend pueda filtrar por moneda
    accounts_list = []
    try:
        c.execute("""
            SELECT id, location, bank, account_type, account_number, currency
            FROM bank_accounts
            WHERE client_id = ?
            ORDER BY id
        """, (client_db_id,))
        acc_rows = c.fetchall()
        for acc in acc_rows:
            accounts_list.append({
                'id': acc[0],
                'location': acc[1],
                'bank': acc[2],
                'account_type': acc[3],
                'account_number': acc[4],
                'currency': acc[5]
            })
    except Exception as e:
        # No interrumpir la respuesta: retornamos lista vacía y dejamos un warning en logs
        current_app.logger.warning(f"[get_operation_full] Error trayendo cuentas para client_id={client_db_id}: {e}")
        accounts_list = []

    # 6) Intentar resolver banco asociado a source_account y destination_account (si existe)
    source_bank = ''
    dest_bank = ''
    try:
        if source_account:
            c.execute("SELECT bank FROM bank_accounts WHERE account_number = ? AND client_id = ? LIMIT 1", (source_account, client_db_id))
            sb = c.fetchone()
            source_bank = sb[0] if sb and sb[0] else ''
    except Exception:
        source_bank = ''

    try:
        if destination_account:
            c.execute("SELECT bank FROM bank_accounts WHERE account_number = ? AND client_id = ? LIMIT 1", (destination_account, client_db_id))
            db = c.fetchone()
            dest_bank = db[0] if db and db[0] else ''
    except Exception:
        dest_bank = ''

    conn.close()

    # Construir y retornar JSON completo
    return jsonify({
        'operation_id': operation_id_db,
        'amount_usd': amount_usd,
        'operation_type': operation_type,
        'client_id': client_db_id,                # id interno (entero)
        'client_public_id': client_public_id,     # id público tipo P00001 (si existe)
        'source_account': source_account,
        'destination_account': destination_account,
        'source_bank': source_bank,
        'dest_bank': dest_bank,
        'trader_file': payment_proof,
        'operation_code': operation_code,
        'status': status,
        'exchange_rate': exchange_rate,
        'amount_pen': amount_pen,
        'modificado': modificado,
        'updated_at': updated_at,
        'created_at': created_at,
        'client_name': client_name,
        'doc_number': doc_number,
        'trader_name': trader_name,
        'operador_file': operador_files_list,
        'operador_comentarios': operador_comentarios or '',
        'abonos': abonos_list,
        'pagos': pagos_list,
        'accounts': accounts_list   # <-- clave nueva que el frontend usa para poblar selects
    })

@app.route('/download_posicion_excel')
@login_required
def download_posicion_excel():
    if current_user.role not in ["Operador", "Master"]:
        return "No autorizado", 403
    
    try:
        import pandas as pd
        from io import BytesIO
        from datetime import datetime

        hoy = now_peru().strftime('%Y-%m-%d')
        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()

        # Obtener datos de COMPRAS
        c.execute("""
            SELECT o.operation_id, c.name, o.amount_usd, o.exchange_rate, o.amount_pen,
                   CASE WHEN IFNULL(o.paid_amount,0)>=o.amount_usd THEN 'SÍ' ELSE 'NO' END as abono,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as banco_cargo,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as banco_destino,
                   o.created_at
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            WHERE o.operation_type = 'Compra' AND DATE(o.created_at) = ?
                AND o.status NOT IN ('Cancelada', 'Cancelado')
            ORDER BY o.created_at DESC
        """, (hoy,))
        compras = c.fetchall()

        # Obtener datos de VENTAS
        c.execute("""
            SELECT o.operation_id, c.name, o.amount_usd, o.exchange_rate, o.amount_pen,
                   CASE WHEN IFNULL(o.paid_amount,0)>=o.amount_usd THEN 'SÍ' ELSE 'NO' END as abono,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as banco_cargo,
                   (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as banco_destino,
                   o.created_at
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            WHERE o.operation_type = 'Venta' AND DATE(o.created_at) = ?
                AND o.status NOT IN ('Cancelada', 'Cancelado')
            ORDER BY o.created_at DESC
        """, (hoy,))
        ventas = c.fetchall()

        # Calcular totales
        total_compra_usd = sum([row[2] for row in compras]) if compras else 0
        total_compra_pen = sum([row[4] for row in compras]) if compras else 0
        total_venta_usd = sum([row[2] for row in ventas]) if ventas else 0
        total_venta_pen = sum([row[4] for row in ventas]) if ventas else 0
        diferencia_usd = total_venta_usd - total_compra_usd
        utilidad_soles = total_venta_pen - total_compra_pen

        conn.close()

        # Crear DataFrames
        compras_columns = ['ID Operación', 'Cliente', 'USD', 'Tipo Cambio', 'Soles', 'Abonado', 'Banco Origen', 'Banco Destino', 'Fecha']
        ventas_columns = ['ID Operación', 'Cliente', 'USD', 'Tipo Cambio', 'Soles', 'Abonado', 'Banco Origen', 'Banco Destino', 'Fecha']
        
        df_compras = pd.DataFrame(compras, columns=compras_columns)
        df_ventas = pd.DataFrame(ventas, columns=ventas_columns)

        # Crear resumen
        resumen_data = {
            'Concepto': ['Total Compras USD', 'Total Ventas USD', 'Diferencia USD', 
                        'Total Compras S/', 'Total Ventas S/', 'Utilidad del Día S/'],
            'Monto': [total_compra_usd, total_venta_usd, diferencia_usd,
                     total_compra_pen, total_venta_pen, utilidad_soles]
        }
        df_resumen = pd.DataFrame(resumen_data)

        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            # Hoja de resumen
            df_resumen.to_excel(writer, index=False, sheet_name='Resumen')
            
            # Hoja de compras
            df_compras.to_excel(writer, index=False, sheet_name='Compras')
            
            # Hoja de ventas
            df_ventas.to_excel(writer, index=False, sheet_name='Ventas')

            # Formatear Excel
            workbook = writer.book
            
            # Formato para encabezados
            header_format = workbook.add_format({
                'bold': True,
                'text_wrap': True,
                'valign': 'top',
                'fg_color': '#b9a038',
                'font_color': 'white',
                'border': 1
            })
            
            # Formato para números
            number_format = workbook.add_format({'num_format': '#,##0.00'})
            currency_usd_format = workbook.add_format({'num_format': '"$"#,##0.00'})
            currency_pen_format = workbook.add_format({'num_format': '"S/"#,##0.00'})
            rate_format = workbook.add_format({'num_format': '#,##0.0000'})
            
            # Aplicar formatos a todas las hojas
            for sheet_name in ['Resumen', 'Compras', 'Ventas']:
                worksheet = writer.sheets[sheet_name]
                
                # Aplicar formato a encabezados
                for col_num, value in enumerate(writer.sheets[sheet_name]._worksheet.__dict__['_worksheet'].get_array()):
                    if col_num == 0:  # Solo la primera fila (encabezados)
                        for row_num, cell_value in enumerate(value):
                            worksheet.write(0, row_num, cell_value, header_format)
                
                # Autoajustar columnas
                for i, col in enumerate(writer.sheets[sheet_name]._worksheet.__dict__['_worksheet'].get_array()[0]):
                    max_len = max(len(str(col)), 12) + 2
                    worksheet.set_column(i, i, min(max_len, 20))
            
            # Formato específico para números en Compras y Ventas
            compras_sheet = writer.sheets['Compras']
            ventas_sheet = writer.sheets['Ventas']
            
            # Formato columnas numéricas
            for sheet in [compras_sheet, ventas_sheet]:
                sheet.set_column(2, 2, 12, currency_usd_format)  # USD
                sheet.set_column(3, 3, 12, rate_format)          # Tipo Cambio
                sheet.set_column(4, 4, 15, currency_pen_format)   # Soles
            
            # Formato para Resumen
            resumen_sheet = writer.sheets['Resumen']
            resumen_sheet.set_column(1, 1, 15, number_format)

        output.seek(0)
        
        # Nombre del archivo con fecha
        filename = f"posicion_{hoy}.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name=filename,
            as_attachment=True
        )
        
    except Exception as e:
        print(f"Error al generar Excel de posición: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return f"Error al generar el archivo: {str(e)}", 500

@app.route('/api/posicion_stats_optimized')
@login_required
def api_posicion_stats_optimized():
    """Versión optimizada del endpoint de posición"""
    if current_user.role not in ["Operador", "Master"]:
        return jsonify({"error": "No autorizado"}), 403
    
    hoy = now_peru().strftime('%Y-%m-%d')
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    
    try:
        # Consulta única optimizada que obtiene compras y ventas en una sola query
        c.execute("""
            SELECT 
                o.operation_type,
                o.operation_id, 
                c.name, 
                o.amount_usd, 
                o.exchange_rate, 
                o.amount_pen,
                CASE WHEN IFNULL(o.paid_amount,0)>=o.amount_usd THEN 1 ELSE 0 END as abono,
                (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as banco_cargo,
                (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as banco_destino,
                SUM(CASE WHEN o.operation_type = 'Compra' THEN o.amount_usd ELSE 0 END) OVER() as total_compra_usd,
                SUM(CASE WHEN o.operation_type = 'Compra' THEN o.amount_pen ELSE 0 END) OVER() as total_compra_pen,
                SUM(CASE WHEN o.operation_type = 'Venta' THEN o.amount_usd ELSE 0 END) OVER() as total_venta_usd,
                SUM(CASE WHEN o.operation_type = 'Venta' THEN o.amount_pen ELSE 0 END) OVER() as total_venta_pen
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            WHERE DATE(o.created_at) = ?
                AND o.operation_type IN ('Compra', 'Venta')
                AND o.status NOT IN ('Cancelada', 'Cancelado')
            ORDER BY o.operation_type, o.created_at DESC
        """, (hoy,))
        
        results = c.fetchall()
        
        # Separar compras y ventas
        compras = []
        ventas = []
        total_compra_usd = 0
        total_compra_pen = 0
        total_venta_usd = 0
        total_venta_pen = 0
        
        if results:
            # Los totales están en las primeras filas (son iguales en todas las filas)
            total_compra_usd = results[0][9] or 0
            total_compra_pen = results[0][10] or 0
            total_venta_usd = results[0][11] or 0
            total_venta_pen = results[0][12] or 0
            
            for row in results:
                op_data = list(row[:9])  # Solo los datos de la operación
                if row[0] == 'Compra':
                    compras.append(op_data)
                else:
                    ventas.append(op_data)
        
        diferencia_usd = total_venta_usd - total_compra_usd
        
        return jsonify({
            "compras": compras,
            "ventas": ventas,
            "total_compra_usd": float(total_compra_usd),
            "total_venta_usd": float(total_venta_usd),
            "total_compra_pen": float(total_compra_pen),
            "total_venta_pen": float(total_venta_pen),
            "diferencia_usd": float(diferencia_usd),
            "utilidad_soles": float(total_venta_pen - total_compra_pen)
        })
        
    except Exception as e:
        print(f"Error en posicion_stats_optimized: {str(e)}")
        return jsonify({"error": "Error interno del servidor"}), 500
    finally:
        conn.close()

@app.route('/download_clients_excel')
@login_required
def download_clients_excel():
    if current_user.role != 'Master':
        return "No autorizado", 403
    
    try:
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')
        
        if not fecha_inicio or not fecha_fin:
            return "Fechas requeridas", 400

        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()
        
        # Consulta para obtener TODOS los datos del cliente
        c.execute('''
            SELECT 
                c.id, c.client_id, c.name, c.doc_type, c.doc_number, c.client_type, 
                c.phone, c.email, c.address, c.created_at, u.username, c.status,
                c.doc_front, c.doc_back, c.doc_ru
            FROM clients c
            LEFT JOIN users u ON c.user_id = u.id
            WHERE DATE(c.created_at) BETWEEN ? AND ?
            ORDER BY c.created_at DESC
        ''', (fecha_inicio, fecha_fin))
        
        clients = c.fetchall()
        
        # Obtener cuentas bancarias para cada cliente
        client_data = []
        for client in clients:
            client_db_id = client[0]  # ID interno de la base de datos
            client_public_id = client[1]  # ID público (P00001)
            
            # Obtener cuentas bancarias del cliente usando el ID interno
            c.execute('''
                SELECT location, bank, account_type, currency, account_number 
                FROM bank_accounts 
                WHERE client_id = ? 
                ORDER BY id
            ''', (client_db_id,))
            
            accounts = c.fetchall()
            
            print(f"DEBUG: Cliente {client_public_id} tiene {len(accounts)} cuentas")  # Debug
            
            # Inicializar datos del cliente
            client_row = {
                'ID CLIENTE': client_public_id,
                'NOMBRE': client[2] or '',
                'TIPO DOC.': client[3] or '',
                'N° DOC': client[4] or '',
                'TIPO CLIENTE': client[5] or '',
                'TELÉFONO': client[6] or '',
                'EMAIL': client[7] or '',
                'DIRECCIÓN': client[8] or '',
                'FECHA REGISTRO': client[9] or '',
                'USUARIO REGISTRÓ': client[10] or '',
                'ESTADO': client[11] or '',
                'DOCUMENTO FRONTAL': 'Sí' if client[12] else 'No',
                'DOCUMENTO REVERSO': 'Sí' if client[13] else 'No',
                'FICHA RUC': 'Sí' if client[14] else 'No'
            }
            
            # Agregar hasta 4 cuentas bancarias
            for i in range(4):
                if i < len(accounts):
                    account = accounts[i]
                    print(f"DEBUG: Cuenta {i+1}: {account}")  # Debug
                    client_row.update({
                        f'UBICACIÓN CUENTA {i+1}': account[0] or '',
                        f'BANCO {i+1}': account[1] or '',
                        f'TIPO CUENTA {i+1}': account[2] or '',
                        f'MONEDA {i+1}': account[3] or '',
                        f'NÚMERO DE CUENTA {i+1}': account[4] or ''
                    })
                else:
                    # Si no hay cuenta en esta posición, dejar vacío
                    client_row.update({
                        f'UBICACIÓN CUENTA {i+1}': '',
                        f'BANCO {i+1}': '',
                        f'TIPO CUENTA {i+1}': '',
                        f'MONEDA {i+1}': '',
                        f'NÚMERO DE CUENTA {i+1}': ''
                    })
            
            client_data.append(client_row)
        
        conn.close()
        
        # Si no hay datos, retornar mensaje
        if not client_data:
            return "No hay datos para el rango de fechas seleccionado", 404
        
        # Debug: mostrar estructura de datos
        print(f"DEBUG: Total de clientes procesados: {len(client_data)}")
        if client_data:
            print(f"DEBUG: Primera fila de datos: {client_data[0]}")
        
        # Crear Excel
        import pandas as pd
        from io import BytesIO
        
        # Crear DataFrame directamente con los datos
        df = pd.DataFrame(client_data)
        
        # Debug: mostrar columnas del DataFrame
        print(f"DEBUG: Columnas del DataFrame: {df.columns.tolist()}")
        
        # Definir el orden de columnas
        expected_columns = [
            'ID CLIENTE', 'NOMBRE', 'TIPO DOC.', 'N° DOC', 'TIPO CLIENTE', 
            'TELÉFONO', 'EMAIL', 'DIRECCIÓN', 'FECHA REGISTRO', 'USUARIO REGISTRÓ', 
            'ESTADO', 'DOCUMENTO FRONTAL', 'DOCUMENTO REVERSO', 'FICHA RUC'
        ]
        
        # Agregar columnas para hasta 4 cuentas
        for i in range(1, 5):
            expected_columns.extend([
                f'UBICACIÓN CUENTA {i}',
                f'BANCO {i}',
                f'TIPO CUENTA {i}',
                f'MONEDA {i}',
                f'NÚMERO DE CUENTA {i}'
            ])
        
        # Asegurarse de que todas las columnas existan en el DataFrame
        for col in expected_columns:
            if col not in df.columns:
                df[col] = ''
        
        # Reordenar columnas
        df = df[expected_columns]
        
        output = BytesIO()
        with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
            df.to_excel(writer, index=False, sheet_name='Clientes')
            
            # Formatear el Excel
            workbook = writer.book
            worksheet = writer.sheets['Clientes']
            
            # Formato para encabezados
            header_format = workbook.add_format({
                'bold': True,
                'text_wrap': True,
                'valign': 'top',
                'fg_color': '#D7E4BC',
                'border': 1
            })
            
            # Aplicar formato a encabezados
            for col_num, value in enumerate(df.columns.values):
                worksheet.write(0, col_num, value, header_format)
            
            # Autoajustar columnas
            for i, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).str.len().max(), len(col)) + 2
                worksheet.set_column(i, i, min(max_len, 20))
        
        output.seek(0)
        
        # Nombre del archivo con fechas
        filename = f"clientes_{fecha_inicio}_a_{fecha_fin}.xlsx"
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name=filename,
            as_attachment=True
        )
        
    except Exception as e:
        print(f"Error al generar Excel: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return f"Error al generar el archivo: {str(e)}", 500

@app.route('/api/operation/<operation_id>/validar_operador', methods=['POST'])
@login_required
def validar_operacion_operador(operation_id):
    if current_user.role != 'Operador':
        return jsonify({'error': 'No autorizado'}), 403

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT status FROM operations WHERE operation_id = ?", (operation_id,))
    row = c.fetchone()
    if not row or row[0] != "En proceso":
        conn.close()
        return jsonify({'error': 'Solo puedes validar operaciones en estado En proceso.'}), 400

    operador_files = request.files.getlist('operador_comprobantes[]')
    operador_comentario = request.form.get('operador_comentario', '').strip()
    if not operador_files or not any(f and f.filename for f in operador_files):
        conn.close()
        return jsonify({'error': 'Debes adjuntar al menos un comprobante.'}), 400

    archivos_guardados = []
    for file in operador_files:
        if file and file.filename:
            filename = secure_filename(f"{operation_id}_operador_{file.filename}")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            archivos_guardados.append(filename)

    # Guarda los archivos y el comentario (puedes usar campos nuevos: operador_file, operador_comentarios)
    c.execute("""
        UPDATE operations
        SET status='Procesado',
            operador_file=?,
            operador_comentarios=?
        WHERE operation_id=?
    """, (",".join(archivos_guardados), operador_comentario, operation_id))
    conn.commit()
    conn.close()
    socketio.emit('operacion_actualizada', {'tipo': 'actualizada', 'operation_id': operation_id})
    return jsonify({'success': True})

@app.route('/api/operation/<operation_id>/add_abono', methods=['POST'])
@login_required
def add_abono(operation_id):
    if current_user.role not in ('Trader', 'Master'):
        return jsonify({"error": "No autorizado"}), 403
    try:
        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()
        c.execute("SELECT status, amount_usd, paid_amount FROM operations WHERE operation_id = ?", (operation_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Operación no encontrada"}), 404
        status_actual, monto_total, abonado_prev = row[0], row[1] or 0, row[2] or 0
        if status_actual != "Pendiente":
            conn.close()
            return jsonify({"error": "Solo puedes registrar abonos si la operación está Pendiente."}), 400

        montos = request.form.getlist('montos[]')
        nro_operaciones = request.form.getlist('nro_operaciones[]')
        cuentas_cargo = request.form.getlist('cuentas_cargo[]')  # <-- AGREGADO
        files = request.files.getlist('adjuntos[]')

        if not (len(montos) == len(nro_operaciones) == len(files) == len(cuentas_cargo)):
            conn.close()
            return jsonify({'error': 'Datos de abono inconsistentes'}), 400

        # Elimina los abonos previos antes de agregar los nuevos
        c.execute("DELETE FROM operation_abonos WHERE operation_id = ?", (operation_id,))

        total_abonado_nuevo = 0
        for i in range(len(montos)):
            monto = float(montos[i])
            nro_op = nro_operaciones[i]
            cuenta_cargo = cuentas_cargo[i] if len(cuentas_cargo) > i else None
            file = files[i]
            filename = None
            if file and file.filename:
                filename = secure_filename(f"{operation_id}_abono_{i}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # AGREGADO: guarda cuenta_cargo en el insert
            c.execute("INSERT INTO operation_abonos (operation_id, amount, nro_operacion, comprobante, cuenta_cargo) VALUES (?, ?, ?, ?, ?)",
                      (operation_id, monto, nro_op, filename, cuenta_cargo))
            total_abonado_nuevo += monto

        suma_total = total_abonado_nuevo
        es_parcial = request.form.get('parcial', '0') == '1'
        nuevo_estado = 'P-En Proceso' if es_parcial else 'En proceso'
        c.execute("UPDATE operations SET status = ?, paid_amount = ? WHERE operation_id = ?", (nuevo_estado, suma_total, operation_id))

        conn.commit()
        conn.close()
        socketio.emit('operacion_actualizada', {'tipo': 'actualizada', 'operation_id': operation_id})
        return jsonify(success=True, abonado=suma_total)
    except Exception as e:
        return str(e), 400

@app.route('/api/operation/<operation_id>/add_pago', methods=['POST'])
@login_required
def add_pago(operation_id):
    if current_user.role not in ('Trader', 'Master'):
        return jsonify({"error": "No autorizado"}), 403
    try:
        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()

        c.execute("SELECT status, amount_usd, exchange_rate FROM operations WHERE operation_id = ?", (operation_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            return jsonify({"error": "Operación no encontrada"}), 404
        status_actual, monto_usd, exchange_rate = row

        # BLOQUE CORREGIDO: Aceptar pagos si la operación está Pendiente, En proceso o P-En Proceso
        if status_actual not in ("Pendiente", "En proceso", "P-En Proceso"):
            conn.close()
            return jsonify({"error": "Solo puedes registrar pagos si la operación está Pendiente o En proceso."}), 400

        montos = request.form.getlist('montos_pagos[]')
        cuentas_destino = request.form.getlist('cuentas_destino[]')

        if not (len(montos) == len(cuentas_destino)):
            conn.close()
            return jsonify({'error': 'Datos de pagos inconsistentes'}), 400

        # Elimina los pagos previos antes de agregar los nuevos
        c.execute("DELETE FROM operation_pagos WHERE operation_id = ?", (operation_id,))

        total_pagado_nuevo = 0
        for i in range(len(montos)):
            monto = float(montos[i])
            cuenta_destino = cuentas_destino[i]
            c.execute("INSERT INTO operation_pagos (operation_id, amount, cuenta_destino) VALUES (?, ?, ?)",
                      (operation_id, monto, cuenta_destino))
            total_pagado_nuevo += monto

        # Puedes actualizar el estado de la operación si lo necesitas aquí

        conn.commit()
        conn.close()
        socketio.emit('operacion_actualizada', {'tipo': 'actualizada', 'operation_id': operation_id})
        return jsonify(success=True, pagado=total_pagado_nuevo)
    except Exception as e:
        return str(e), 400

@app.route('/api/operation/<operation_id>/pagos')
@login_required
def pagos_por_operacion(operation_id):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT amount, cuenta_destino, created_at FROM operation_pagos WHERE operation_id = ?", (operation_id,))
    pagos = c.fetchall()
    conn.close()
    pagos_list = [{
        'amount': p[0],
        'cuenta_destino': p[1],
        'created_at': p[2]
    } for p in pagos]
    return jsonify({'pagos': pagos_list})

@app.route('/api/operation/<operation_id>/abonos')
@login_required
def abonos_por_operacion(operation_id):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT amount, nro_operacion, comprobante, created_at FROM operation_abonos WHERE operation_id = ?", (operation_id,))
    abonos = c.fetchall()
    conn.close()
    abonos_list = [{
        'amount': a[0],
        'nro_operacion': a[1],
        'comprobante': a[2],
        'created_at': a[3]
    } for a in abonos]
    return jsonify({'abonos': abonos_list})

@app.route('/api/operation/<operation_id>')
@login_required
def api_get_operation(operation_id):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT amount_usd, exchange_rate, amount_pen FROM operations WHERE operation_id = ?", (operation_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "amount_usd": row[0],
        "exchange_rate": row[1],
        "amount_pen": row[2]
    })

@app.route('/api/operation/<operation_id>/modificar_importe', methods=['POST'])
@login_required
def modificar_importe(operation_id):
    try:
        # Obtén amount_usd tanto de form como de json
        nuevo_importe_str = request.form.get('amount_usd')
        if nuevo_importe_str is None:
            data = request.get_json(silent=True)
            if data and 'amount_usd' in data:
                nuevo_importe_str = str(data['amount_usd'])
            else:
                print("FALTA amount_usd")
                return "Falta amount_usd", 400
        nuevo_importe_str = nuevo_importe_str.replace(',', '')
        try:
            nuevo_importe = float(nuevo_importe_str)
        except Exception:
            print("IMPORTE INVÁLIDO:", nuevo_importe_str)
            return "Importe inválido", 400

        conn = sqlite3.connect('dollar_trading.db')
        c = conn.cursor()

        # Verifica que exista la operación
        c.execute("SELECT exchange_rate FROM operations WHERE operation_id = ?", (operation_id,))
        row = c.fetchone()
        if not row:
            conn.close()
            print("OPERACION NO ENCONTRADA:", operation_id)
            return "Operación no encontrada", 404

        tipo_cambio = row[0]
        nuevo_contravalor = nuevo_importe * tipo_cambio

        c.execute('''
            UPDATE operations 
            SET amount_usd = ?, amount_pen = ?, modificado = 1, updated_at = ?
            WHERE operation_id = ?
        ''', (nuevo_importe, nuevo_contravalor, now_peru().strftime('%Y-%m-%d %H:%M:%S'), operation_id))
        conn.commit()
        conn.close()
        socketio.emit('operacion_actualizada', {'tipo': 'actualizada', 'operation_id': operation_id})
        print("ACTUALIZADO OK")
        return jsonify(success=True)
    except Exception as e:
        import traceback
        print(traceback.format_exc())
        return str(e), 400

@app.route('/api/set_trader_stats', methods=['POST'])
@login_required
def api_set_trader_stats():
    if current_user.role != 'Master':
        return jsonify({'success': False, 'msg': 'No autorizado'}), 403
    
    try:
        # Obtener datos del formulario
        trader_id = int(request.form.get('trader_id'))
        year_month = request.form.get('year_month')
        
        # Validar que los campos requeridos estén presentes
        if not trader_id or not year_month:
            return jsonify({'success': False, 'msg': 'Faltan campos requeridos: trader_id o year_month'}), 400
        
        # Solo recoge los campos realmente enviados
        fields = {}
        for k in ['utilidad_dia', 'utilidad_mes', 'meta_mes']:
            v = request.form.get(k, None)
            if v not in [None, ""]:
                try:
                    # Convertir a float, permitiendo decimales
                    v = float(v)
                    fields[k] = v
                except ValueError:
                    return jsonify({'success': False, 'msg': f'Formato numérico inválido para {k}'}), 400
        
        # Si no hay campos para actualizar, retornar error
        if not fields:
            return jsonify({'success': False, 'msg': 'No hay datos para guardar.'}), 400
        
        # Guardar solo los campos que vinieron
        set_trader_stats(trader_id, year_month, **fields)
        return jsonify({'success': True, 'msg': 'Datos guardados correctamente'})
    
    except Exception as e:
        return jsonify({'success': False, 'msg': f'Error del servidor: {str(e)}'}), 500

@app.route('/api/dashboard_data')
@login_required
def api_dashboard_data():
    # Soporta filtro por trader (solo para operador/master) y por mes
    filtro_trader_id = request.args.get('trader_id', type=int)
    filtro_mes = request.args.get('month', '')  # Nuevo parámetro para filtrar por mes
    
    role = current_user.role
    today = now_peru().strftime('%Y-%m-%d')
    
    # Determinar el mes a usar (si viene filtro_mes, usarlo, sino mes actual)
    if filtro_mes:
        year_month = filtro_mes
        # Validar que el formato sea YYYY-MM
        try:
            datetime.strptime(filtro_mes, '%Y-%m')
        except ValueError:
            year_month = get_year_month()  # Fallback al mes actual
    else:
        year_month = get_year_month()
    
    # Calcular primer día del mes seleccionado
    try:
        primer_dia_mes = datetime.strptime(year_month, '%Y-%m').replace(day=1).strftime('%Y-%m-%d')
    except:
        primer_dia_mes = now_peru().replace(day=1).strftime('%Y-%m-%d')
    
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    
    # Determinar si estamos en modo "Todos" los traders
    modo_todos = filtro_trader_id is None and role in ('Master', 'Operador')
    trader_id = filtro_trader_id if filtro_trader_id and role in ('Master','Operador') else (current_user.id if role == 'Trader' else None)

    # Condición para filtrar por trader
    trader_cond = ""
    params = []
    if trader_id:
        trader_cond = " AND c.user_id = ?"
        params.append(trader_id)

    # CLIENTES NUEVOS DEL DÍA (siempre muestra el día actual, independiente del mes seleccionado)
    c.execute(f"""
        SELECT COUNT(*)
        FROM clients c
        WHERE DATE(c.created_at) = ?
          AND EXISTS (
            SELECT 1 FROM operations o
            WHERE o.client_id = c.id AND o.status='Procesado'
          )
          {trader_cond}
    """, [today] + params)
    clients_today = c.fetchone()[0]

    # CLIENTES NUEVOS DEL MES (usar el mes seleccionado)
    c.execute(f"""
        SELECT COUNT(*)
        FROM clients c
        WHERE DATE(c.created_at) >= ? AND DATE(c.created_at) < date(?, '+1 month')
          AND EXISTS (
            SELECT 1 FROM operations o
            WHERE o.client_id = c.id AND o.status='Procesado'
          )
          {trader_cond}
    """, [primer_dia_mes, primer_dia_mes] + params)
    clients_month = c.fetchone()[0]

    # OPERACIONES DEL DÍA (siempre muestra el día actual)
    c.execute(f"""
        SELECT COUNT(*), IFNULL(SUM(amount_usd),0), IFNULL(SUM(amount_pen),0)
        FROM operations o
        JOIN clients c ON o.client_id = c.id
        WHERE DATE(o.created_at) = ?
          {trader_cond}
          AND o.status NOT IN ('Cancelada', 'Anulada')
    """, [today] + params)
    operations_today, usd_today, pen_today = c.fetchone()

    # OPERACIONES DEL MES (usar el mes seleccionado)
    c.execute(f"""
        SELECT COUNT(*), IFNULL(SUM(amount_usd),0), IFNULL(SUM(amount_pen),0)
        FROM operations o
        JOIN clients c ON o.client_id = c.id
        WHERE DATE(o.created_at) >= ? AND DATE(o.created_at) < date(?, '+1 month')
          {trader_cond}
          AND o.status NOT IN ('Cancelada', 'Anulada')
    """, [primer_dia_mes, primer_dia_mes] + params)
    operations_month, usd_month, pen_month = c.fetchone()

    # CLIENTES ACTIVOS DEL MES (al menos una operación PROCESADO en el mes seleccionado)
    c.execute(f"""
        SELECT COUNT(DISTINCT c.id)
        FROM clients c
        JOIN operations o ON o.client_id = c.id
        WHERE DATE(o.created_at) >= ? AND DATE(o.created_at) < date(?, '+1 month')
          AND o.status='Procesado'
          {trader_cond}
    """, [primer_dia_mes, primer_dia_mes] + params)
    active_clients_month = c.fetchone()[0]

    # TRAER UTILIDAD Y META - MODIFICADO PARA MODO "TODOS"
    if modo_todos:
        # Sumar las utilidades y metas de todos los traders para el mes seleccionado
        c.execute("""
            SELECT 
                SUM(utilidad_dia) as total_utilidad_dia,
                SUM(utilidad_mes) as total_utilidad_mes,
                SUM(meta_mes) as total_meta_mes
            FROM trader_stats 
            WHERE year_month = ?
        """, (year_month,))
        stats_row = c.fetchone()
        utilidad_dia = stats_row[0] if stats_row and stats_row[0] is not None else 0
        utilidad_mes = stats_row[1] if stats_row and stats_row[1] is not None else 0
        meta_mes = stats_row[2] if stats_row and stats_row[2] is not None else 0
    else:
        # Traer stats del trader específico para el mes seleccionado
        stats = get_trader_stats(trader_id or 0, year_month)
        utilidad_dia = stats['utilidad_dia']
        utilidad_mes = stats['utilidad_mes']
        meta_mes = stats['meta_mes']

    # Porcentaje de avance respecto a meta
    avance = 0
    if meta_mes > 0:
        avance = min(100, round(utilidad_mes * 100 / meta_mes, 2))

    # Listado de traders (solo para operador/master)
    traders = []
    if role in ('Master','Operador'):
        c.execute("SELECT id, username FROM users WHERE role='Trader' AND status='Activo' ORDER BY username")
        traders = [{'id': t[0], 'username': t[1]} for t in c.fetchall()]

    conn.close()
    
    return jsonify({
        "role": role,
        "trader_id": trader_id,
        "modo_todos": modo_todos,
        "selected_month": year_month,  # Nuevo campo para indicar el mes seleccionado
        "traders": traders,
        "clients_today": clients_today,
        "clients_month": clients_month,
        "operations_today": operations_today,
        "operations_month": operations_month,
        "usd_today": float(usd_today or 0),
        "usd_month": float(usd_month or 0),
        "pen_today": float(pen_today or 0),
        "pen_month": float(pen_month or 0),
        "active_clients_month": active_clients_month,
        "utilidad_dia": float(utilidad_dia or 0),
        "utilidad_mes": float(utilidad_mes or 0),
        "meta_mes": float(meta_mes or 0),
        "avance": avance
    })

@app.route('/download_operations')
@login_required
def download_operations():
    import pandas as pd
    from io import BytesIO

    client_filter = request.args.get('client', '')
    date_filter = request.args.get('date', '')

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Armar query base
    query = '''SELECT o.operation_id, c.doc_number, c.name, o.operation_type,
                      o.amount_usd, o.exchange_rate, o.amount_pen,
                      o.source_account, o.destination_account, o.status, o.created_at
               FROM operations o
               JOIN clients c ON o.client_id = c.id'''
    params = []
    where = []

    # FILTRO SOLO OPERACIONES DEL TRADER LOGUEADO
    if current_user.role == 'Trader':
        where.append('c.user_id = ?')
        params.append(current_user.id)

    # Filtros de búsqueda (cliente, fecha)
    if client_filter:
        where.append('(c.doc_number LIKE ? OR c.name LIKE ?)')
        params.extend([f'%{client_filter}%', f'%{client_filter}%'])
    if date_filter:
        where.append('DATE(o.created_at) = ?')
        params.append(date_filter)

    if where:
        query += " WHERE " + " AND ".join(where)
    query += " ORDER BY o.created_at DESC"

    c.execute(query, params)
    ops = c.fetchall()
    conn.close()

    # Columnas en el mismo orden que la tabla
    columns = ['ID Operación', 'Documento', 'Cliente', 'Tipo', 'USD', 'Tipo Cambio',
               'Soles', 'Cuenta Origen', 'Cuenta Destino', 'Estado', 'Fecha']
    df = pd.DataFrame(ops, columns=columns)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Operaciones')
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     download_name="operaciones.xlsx", as_attachment=True)

@app.route('/api/operations_history')
@login_required
def operations_history():
    client_filter = request.args.get('client', '')
    date_filter = request.args.get('date', '')
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Construir consulta con filtros
    base_query = '''SELECT o.operation_id, c.doc_number, c.name, o.operation_type, 
                      o.amount_usd, o.exchange_rate, o.amount_pen, 
                      o.source_account, o.destination_account, o.status, o.created_at
               FROM operations o 
               JOIN clients c ON o.client_id = c.id'''
    where_clauses = []
    params = []

    # Filtro por trader (solo mostrar operaciones de sus clientes)
    if current_user.role == 'Trader':
        where_clauses.append('c.user_id = ?')
        params.append(current_user.id)

    # Filtro por búsqueda de cliente (nombre o doc)
    if client_filter:
        where_clauses.append('(c.doc_number LIKE ? OR c.name LIKE ?)')
        params.extend([f'%{client_filter}%', f'%{client_filter}%'])

    # Filtro por fecha
    if date_filter:
        where_clauses.append('DATE(o.created_at) = ?')
        params.append(date_filter)

    # Unir cláusulas WHERE
    if where_clauses:
        base_query += ' WHERE ' + ' AND '.join(where_clauses)
    base_query += ' ORDER BY o.created_at DESC'

    c.execute(base_query, params)
    operations = c.fetchall()
    conn.close()

    # Convertir a formato JSON
    operations_list = []
    for op in operations:
        operations_list.append({
            'operation_id': op[0],
            'doc_number': op[1],
            'client_name': op[2],
            'operation_type': op[3],
            'amount_usd': op[4],
            'exchange_rate': op[5],
            'amount_pen': op[6],
            'source_account': op[7],
            'destination_account': op[8],
            'status': op[9],
            'created_at': op[10]
        })

    return jsonify(operations=operations_list)
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'Master':
        flash('Acceso denegado')
        return redirect(url_for('dashboard'))
    
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    if request.method == 'POST':
        nombres = request.form.get('nombres', '').strip()
        dni = request.form.get('dni', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('role')
        status = request.form.get('status')

        if not nombres or not dni or not email or not password or not role or not status:
            flash('Todos los campos son obligatorios')
        else:
            c.execute("SELECT 1 FROM users WHERE username = ? OR email = ? OR dni = ?", (nombres, email, dni))
            if c.fetchone():
                flash('El usuario, correo o DNI ya existe')
            else:
                # Guardar la contraseña y la versión en claro (según tu requerimiento)
                c.execute(
                    "INSERT INTO users (username, password, role, dni, email, status, last_plain_password) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (nombres, generate_password_hash(password), role, dni, email, status, password))
                conn.commit()
                flash('Usuario creado exitosamente')

    # Comprobamos qué columnas existen realmente en la tabla users (para compatibilidad con DB antiguas)
    c.execute("PRAGMA table_info(users)")
    cols = [r[1] for r in c.fetchall()]

    # Construir SELECT dinámico: si una columna no existe se selecciona NULL AS <col>
    select_cols = []
    # columnas que queremos en el output y su nombre de alias
    wanted = [
        ('id','id'),
        ('username','username'),
        ('role','role'),
        ('dni','dni'),
        ('email','email'),
        ('status','status'),
        ('created_at','created_at'),
        ('last_login','last_login'),
        ('last_logout','last_logout'),
        ('last_plain_password','last_plain_password')
    ]
    for col_name, alias in wanted:
        if col_name in cols:
            select_cols.append(f"{col_name} AS {alias}")
        else:
            # Si no existe, devolver NULL (o cadena vacía para compatibilidad posterior)
            # usamos NULL para permitir casting en Python
            select_cols.append(f"NULL AS {alias}")

    # Si created_at existe, ordenamos por created_at, si no por id
    order_by = "created_at DESC" if 'created_at' in cols else "id DESC"
    select_sql = f"SELECT {', '.join(select_cols)} FROM users ORDER BY {order_by}"
    c.execute(select_sql)
    rows = c.fetchall()

    users = []
    for r in rows:
        # r es una tupla con los aliases en el mismo orden que wanted
        users.append({
            'id': r[0],
            'username': r[1],
            'role': r[2],
            'dni': r[3],
            'email': r[4],
            'status': r[5],
            'created_at': r[6] or '',
            'last_login': r[7] or '',
            'last_logout': r[8] or '',
            'last_plain_password': r[9] or ''
        })
    conn.close()
    return render_template('manage_users.html', user=current_user, users=users)

@app.route('/reset_password_user', methods=['POST'])
@login_required
def reset_password_user():
    user_id = request.form['user_id']
    # Contraseña por defecto para reset: 'experion123'
    new_plain = 'experion123'
    new_password_hash = generate_password_hash(new_plain)
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("UPDATE users SET password=?, last_plain_password=? WHERE id=?", (new_password_hash, new_plain, user_id))
    conn.commit()
    conn.close()
    # Emitir evento user_updated para que la tabla se actualice en tiempo real
    try:
        socketio.emit('user_updated', {
            'user_id': int(user_id),
            'last_plain_password': new_plain,
            'status': 'Activo'
        }, broadcast=True)
    except Exception:
        pass
    return jsonify(msg=f"Contraseña reseteada a {new_plain}")

@app.route('/edit_user', methods=['POST'])
@login_required
def edit_user():
    # Asegurar permisos: solo Master puede editar usuarios (si es tu policy)
    if getattr(current_user, "role", None) != 'Master':
        return jsonify(msg="No tienes permisos para editar usuarios."), 403

    if request.is_json:
        data = request.get_json()
        user_id = data.get('id')
        nombres = data.get('nombres')
        dni = data.get('dni')
        email = data.get('email')
        role = data.get('role')
        status = data.get('status')
    else:
        user_id = request.form.get('id')
        nombres = request.form.get('nombres')
        dni = request.form.get('dni')
        email = request.form.get('email')
        role = request.form.get('role')
        status = request.form.get('status')

    if not user_id:
        return jsonify(msg="Falta id de usuario"), 400

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Validar unicidad de email/dni
    c.execute("SELECT id FROM users WHERE (LOWER(email) = LOWER(?) OR dni = ?) AND id != ?", (email, dni, user_id))
    if c.fetchone():
        conn.close()
        return jsonify(msg="El correo o DNI ya está registrado en otro usuario."), 400

    try:
        # Si el admin reactiva o pone en 'Pendiente', resetear contador de intentos fallidos
        if status in ('Activo', 'Pendiente'):
            c.execute("UPDATE users SET username=?, dni=?, email=?, role=?, status=?, failed_attempts = 0 WHERE id=?",
                (nombres, dni, email, role, status, user_id))
        else:
            c.execute("UPDATE users SET username=?, dni=?, email=?, role=?, status=? WHERE id=?",
                (nombres, dni, email, role, status, user_id))
        conn.commit()
    except Exception as e:
        conn.rollback()
        conn.close()
        return jsonify(msg="Error al actualizar usuario: " + str(e)), 500

    conn.close()
    return jsonify(msg="Usuario actualizado correctamente.")

@app.route('/get_user/<int:user_id>')
@login_required
def get_user(user_id):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    # Incluimos last_login en la consulta para que el frontend lo muestre
    c.execute("SELECT id, username, dni, email, role, status, last_login FROM users WHERE id=?", (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return jsonify({
            "id": user[0],
            "username": user[1],
            "dni": user[2],
            "email": user[3],
            "role": user[4],
            "status": user[5],
            "last_login": user[6]
        })
    else:
        return jsonify({}), 404

@app.route('/get_client/<client_id>')
@login_required
def get_client(client_id):
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    c.execute("SELECT * FROM clients WHERE client_id = ?", (client_id,))
    client = c.fetchone()
    c.execute("SELECT * FROM bank_accounts WHERE client_id = ?", (client[0],))
    accounts = c.fetchall()
    conn.close()
    return render_template('client_modal.html', client=client, accounts=accounts)

@app.route('/operador_dashboard')
@login_required
def operador_dashboard():
    if current_user.role != "Operador":
        return redirect(url_for('dashboard'))

    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    today = now_peru().strftime('%Y-%m-%d')
    first_day_month = now_peru().replace(day=1).strftime('%Y-%m-%d')

    c.execute("SELECT COUNT(*) FROM clients")
    clients_month = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM clients WHERE DATE(created_at) = ?", (today,))
    clients_today = c.fetchone()[0]

    c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0) 
                 FROM operations 
                 WHERE DATE(created_at) = ?""", (today,))
    operations_today, usd_today, pen_today = c.fetchone()
    c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0) 
                 FROM operations 
                 WHERE DATE(created_at) >= ?""", (first_day_month,))
    operations_month, usd_month, pen_month = c.fetchone()

    c.execute("""
        SELECT o.*, c.name, c.doc_number
        FROM operations o
        JOIN clients c ON o.client_id = c.id
        WHERE DATE(o.created_at) = ? AND o.status = 'Pendiente'
        ORDER BY o.created_at DESC
    """, (today,))
    pending_operations = c.fetchall()
    conn.close()

    return render_template('operador_dashboard.html',
                           user=current_user,
                           clients_today=clients_today,
                           clients_month=clients_month,
                           operations_today=operations_today,
                           operations_month=operations_month,
                           usd_today=usd_today,
                           usd_month=usd_month,
                           pen_today=pen_today,
                           pen_month=pen_month,
                           pending_operations=pending_operations)

@app.route('/posicion')
@login_required
def posicion():
    if current_user.role not in ["Operador", "Master"]:
        return redirect(url_for('dashboard'))

    hoy = now_peru().strftime('%Y-%m-%d')
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()

    # Consulta para COMPRAS con bancos
    c.execute("""
        SELECT o.operation_id, c.name, o.amount_usd, o.exchange_rate, o.amount_pen,
               CASE WHEN IFNULL(o.paid_amount,0)>=o.amount_usd THEN 1 ELSE 0 END as abono,
               (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as banco_cargo,
               (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as banco_destino
        FROM operations o
        JOIN clients c ON o.client_id = c.id
        WHERE o.operation_type = 'Compra' AND DATE(o.created_at) = ?
            AND o.status NOT IN ('Cancelada', 'Cancelado')
        ORDER BY o.created_at DESC
    """, (hoy,))
    compras = c.fetchall()

    # Consulta para VENTAS con bancos
    c.execute("""
        SELECT o.operation_id, c.name, o.amount_usd, o.exchange_rate, o.amount_pen,
               CASE WHEN IFNULL(o.paid_amount,0)>=o.amount_usd THEN 1 ELSE 0 END as abono,
               (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as banco_cargo,
               (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as banco_destino
        FROM operations o
        JOIN clients c ON o.client_id = c.id
        WHERE o.operation_type = 'Venta' AND DATE(o.created_at) = ?
            AND o.status NOT IN ('Cancelada', 'Cancelado')
        ORDER BY o.created_at DESC
    """, (hoy,))
    ventas = c.fetchall()

    total_compra_usd = sum([row[2] for row in compras]) if compras else 0
    total_compra_pen = sum([row[4] for row in compras]) if compras else 0
    total_venta_usd = sum([row[2] for row in ventas]) if ventas else 0
    total_venta_pen = sum([row[4] for row in ventas]) if ventas else 0
    diferencia_usd = total_venta_usd - total_compra_usd

    conn.close()

    return render_template('posicion.html',
        user=current_user,
        fecha_actual=hoy,
        compras=compras,
        ventas=ventas,
        total_compra_usd=total_compra_usd,
        total_compra_pen=total_compra_pen,
        total_venta_usd=total_venta_usd,
        total_venta_pen=total_venta_pen,
        diferencia_usd=diferencia_usd
    )

@app.route('/api/dashboard_stats')
@login_required
def api_dashboard_stats():
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    today = now_peru().strftime('%Y-%m-%d')
    first_day_month = now_peru().replace(day=1).strftime('%Y-%m-%d')
    if current_user.role == 'Trader':
        c.execute("SELECT COUNT(*) FROM clients WHERE user_id = ?", (current_user.id,))
        clients_month = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM clients WHERE user_id = ? AND DATE(created_at) = ?", (current_user.id, today))
        clients_today = c.fetchone()[0]
        c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0)
                     FROM operations
                     WHERE client_id IN (SELECT id FROM clients WHERE user_id = ?)
                       AND DATE(created_at) = ?""", (current_user.id, today))
        operations_today, usd_today, pen_today = c.fetchone()
        c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0)
                     FROM operations
                     WHERE client_id IN (SELECT id FROM clients WHERE user_id = ?)
                       AND DATE(created_at) >= ?
                       AND status NOT IN ('Cancelada', 'Anulada')""", (current_user.id, first_day_month))
        operations_month, usd_month, pen_month = c.fetchone()
    else:
        c.execute("SELECT COUNT(*) FROM clients WHERE DATE(created_at) = ?", (today,))
        clients_today = c.fetchone()[0] or 0
        c.execute("SELECT COUNT(*) FROM clients WHERE DATE(created_at) >= ?", (first_day_month,))
        clients_month = c.fetchone()[0] or 0
        c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0)
                     FROM operations
                     WHERE DATE(created_at) = ?
                       AND status NOT IN ('Cancelada', 'Anulada')""", (today,))
        operations_today, usd_today, pen_today = c.fetchone()
        c.execute("""SELECT COUNT(*), IFNULL(SUM(amount_usd), 0), IFNULL(SUM(amount_pen), 0)
                     FROM operations
                     WHERE DATE(created_at) >= ?
                       AND status NOT IN ('Cancelada', 'Anulada')""", (first_day_month,))
        operations_month, usd_month, pen_month = c.fetchone()
    conn.close()
    return jsonify({
        "clients_today": clients_today,
        "clients_month": clients_month,
        "operations_today": operations_today,
        "operations_month": operations_month,
        "usd_today": float(usd_today or 0),
        "usd_month": float(usd_month or 0),
        "pen_today": float(pen_today or 0),
        "pen_month": float(pen_month or 0)
    })

@app.route('/api/pending_operations')
@login_required
def api_pending_operations():
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    today = now_peru().strftime('%Y-%m-%d')
    if current_user.role == 'Trader':
        c.execute("""
            SELECT o.*, c.name, c.doc_number
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            WHERE c.user_id = ? AND DATE(o.created_at) = ? AND o.status = 'Pendiente'
            ORDER BY o.created_at DESC
        """, (current_user.id, today))
    else:
        c.execute("""
            SELECT o.*, c.name, c.doc_number
            FROM operations o
            JOIN clients c ON o.client_id = c.id
            WHERE DATE(o.created_at) = ? AND o.status = 'Pendiente'
            ORDER BY o.created_at DESC
        """, (today,))
    pending_operations = c.fetchall()
    conn.close()
    # Este endpoint devuelve una lista de tuplas, es usado por dashboards para mostrar las pendientes del día.
    return jsonify(pending_operations)

@app.route('/api/posicion_stats')
@login_required
def api_posicion_stats():
    if current_user.role not in ["Operador", "Master"]:
        return jsonify({"error": "No autorizado"}), 403
    hoy = now_peru().strftime('%Y-%m-%d')
    conn = sqlite3.connect('dollar_trading.db')
    c = conn.cursor()
    
    # Consulta para COMPRAS - incluyendo bancos de cargo y destino
    c.execute("""
        SELECT o.operation_id, c.name, o.amount_usd, o.exchange_rate, o.amount_pen,
               CASE WHEN IFNULL(o.paid_amount,0)>=o.amount_usd THEN 1 ELSE 0 END as abono,
               (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as banco_cargo,
               (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as banco_destino
        FROM operations o
        JOIN clients c ON o.client_id = c.id
        WHERE o.operation_type = 'Compra' AND DATE(o.created_at) = ?
            AND o.status NOT IN ('Cancelada', 'Cancelado')
        ORDER BY o.created_at DESC
    """, (hoy,))
    compras = c.fetchall()
    
    # Consulta para VENTAS - incluyendo bancos de cargo y destino
    c.execute("""
        SELECT o.operation_id, c.name, o.amount_usd, o.exchange_rate, o.amount_pen,
               CASE WHEN IFNULL(o.paid_amount,0)>=o.amount_usd THEN 1 ELSE 0 END as abono,
               (SELECT bank FROM bank_accounts WHERE account_number = o.source_account AND client_id = o.client_id LIMIT 1) as banco_cargo,
               (SELECT bank FROM bank_accounts WHERE account_number = o.destination_account AND client_id = o.client_id LIMIT 1) as banco_destino
        FROM operations o
        JOIN clients c ON o.client_id = c.id
        WHERE o.operation_type = 'Venta' AND DATE(o.created_at) = ?
            AND o.status NOT IN ('Cancelada', 'Cancelado')
        ORDER BY o.created_at DESC
    """, (hoy,))
    ventas = c.fetchall()
    
    total_compra_usd = sum([row[2] for row in compras]) if compras else 0
    total_compra_pen = sum([row[4] for row in compras]) if compras else 0
    total_venta_usd = sum([row[2] for row in ventas]) if ventas else 0
    total_venta_pen = sum([row[4] for row in ventas]) if ventas else 0
    diferencia_usd = total_venta_usd - total_compra_usd
    conn.close()
    return jsonify({
        "compras": compras,
        "ventas": ventas,
        "total_compra_usd": float(total_compra_usd),
        "total_venta_usd": float(total_venta_usd),
        "total_compra_pen": float(total_compra_pen),
        "total_venta_pen": float(total_venta_pen),
        "diferencia_usd": float(diferencia_usd)
    })

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
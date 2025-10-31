import sqlite3

# Cambia la ruta a la de tu base de datos si es distinta
DB_PATH = 'dollar_trading.db'

def actualizar_idop_secuencial(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Selecciona todas las operaciones ordenadas por fecha de creación ascendente
    c.execute("SELECT id FROM operations ORDER BY datetime(created_at) ASC")
    operaciones = c.fetchall()

    for idx, (op_id,) in enumerate(operaciones, start=1001):
        new_idop = f"EXP-{idx:04d}"  # Por ejemplo: EXP-1001, EXP-1002, etc.
        c.execute("UPDATE operations SET operation_id = ? WHERE id = ?", (new_idop, op_id))

    conn.commit()
    conn.close()
    print("Se actualizaron los IDOPs de las operaciones de forma secuencial.")

if __name__ == "__main__":
    actualizar_idop_secuencial(DB_PATH)
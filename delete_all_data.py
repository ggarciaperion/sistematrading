import sqlite3

DB_PATH = 'dollar_trading.db'

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

# Borra todas las operaciones
c.execute("DELETE FROM operations")
# Borra todas las cuentas bancarias
c.execute("DELETE FROM bank_accounts")
# Borra todos los clientes
c.execute("DELETE FROM clients")

conn.commit()
conn.close()

print("¡Todos los registros de operaciones, clientes y cuentas bancarias han sido eliminados!")
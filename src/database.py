from psycopg2 import pool
import os
from dotenv import load_dotenv
from contextlib import contextmanager

# Load environment variables
load_dotenv()

# Global Connection Pool
_pool = None

def init_db_pool(min_conn=1, max_conn=10):
    """Initializes the database connection pool."""
    global _pool
    database_url = os.getenv("DATABASE_URL")
    
    try:
        if database_url:
            _pool = pool.SimpleConnectionPool(min_conn, max_conn, dsn=database_url, sslmode='disable')
        else:
            _pool = pool.SimpleConnectionPool(
                min_conn, max_conn,
                host=os.getenv("DB_HOST", "127.0.0.1"),
                port=os.getenv("DB_PORT", "5433"),
                user="postgres",
                password=os.getenv("DB_PASSWORD"),
                database="emergency_db",
                sslmode='disable' 
            )
        print("✅ Database Connection Pool Created")
    except Exception as e:
        print(f"❌ Error creating connection pool: {e}")
        raise e

def get_db_connection():
    """
    Retrieves a connection from the pool.
    IMPORTANT: Caller must return connection to pool using put_db_connection(conn)
    """
    global _pool
    if _pool is None:
        init_db_pool()
    return _pool.getconn()

def put_db_connection(conn):
    """Returns a connection to the pool."""
    global _pool
    if _pool:
        _pool.putconn(conn)

def close_db_pool():
    """Closes all connections in the pool."""
    global _pool
    if _pool:
        _pool.closeall()
        print("🛑 Database Connection Pool Closed")

# Context manager for easier usage
@contextmanager
def get_db():
    conn = get_db_connection()
    try:
        yield conn
    finally:
        put_db_connection(conn)
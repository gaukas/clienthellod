from psycopg_pool import ConnectionPool # pip install psycopg_pool

class PSQL:
    def __init__(self):
        self.pool = None
    
    def connect(self, db, user, host, password = None, port = None):
        # build connection string
        userspec = f'{user}:{password}' if password else user
        hostspec = f'{host}:{port}' if port else f'{host}'
        conninfo = f'postgresql://{userspec}@{hostspec}/{db}'

        self.pool = ConnectionPool(conninfo)
    
    def conn(self):
        if self.pool is None:
            raise Exception('PSQL is not connected')
        
        with self.pool.connection() as conn:
            return conn
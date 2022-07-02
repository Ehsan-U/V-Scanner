DB2 = 'IBM DB2 database'
MSSQL = 'Microsoft SQL database'
ORACLE = 'Oracle database'
SYBASE = 'Sybase database'
POSTGRE = 'PostgreSQL database'
MYSQL = 'MySQL database'
JAVA = 'Java connector'
ACCESS = 'Microsoft Access database'
INFORMIX = 'Informix database'
INTERBASE = 'Interbase database'
DMLDATABASE = 'DML Language database'
SQLITE = 'SQLite database'
UNKNOWN = 'Unknown database'

SQL_ERRORS_STR =(
    (r'System.Data.OleDb.OleDbException', MSSQL),
    (r'[SQL Server]', MSSQL),
    (r'[Microsoft][ODBC SQL Server Driver]', MSSQL),
    (r'[SQLServer JDBC Driver]', MSSQL),
    (r'[SqlException', MSSQL),
    (r'System.Data.SqlClient.SqlException', MSSQL),
    (r'Unclosed quotation mark after the character string', MSSQL),
    (r"'80040e14'", MSSQL),
    (r'mssql_query()', MSSQL),
    (r'odbc_exec()', MSSQL),
    (r'Microsoft OLE DB Provider for ODBC Drivers', MSSQL),
    (r'Microsoft OLE DB Provider for SQL Server', MSSQL),
    (r'Incorrect syntax near', MSSQL),
    (r'Sintaxis incorrecta cerca de', MSSQL),
    (r'Syntax error in string in query expression', MSSQL),
    (r'ADODB.Field (0x800A0BCD)<br>', MSSQL),
    (r"ADODB.Recordset'", MSSQL),
    (r"Unclosed quotation mark before the character string", MSSQL),
    (r"'80040e07'", MSSQL),
    (r'Microsoft SQL Native Client error', MSSQL),
    (r'SQL Server Native Client', MSSQL),
    (r'Invalid SQL statement', MSSQL),

    # Access
    (r'Syntax error in query expression', ACCESS),
    (r'Data type mismatch in criteria expression.', ACCESS),
    (r'Microsoft JET Database Engine', ACCESS),
    (r'[Microsoft][ODBC Microsoft Access Driver]', ACCESS),

    # ORACLE
    (r'Microsoft OLE DB Provider for Oracle', ORACLE),
    (r'wrong number or types', ORACLE),

    # POSTGRE
    (r'PostgreSQL query failed:', POSTGRE),
    (r'supplied argument is not a valid PostgreSQL result', POSTGRE),
    (r'unterminated quoted string at or near', POSTGRE),
    (r'pg_query() [:', POSTGRE),
    (r'pg_exec() [:', POSTGRE),

    # MYSQL
    (r'supplied argument is not a valid MySQL', MYSQL),
    (r'Column count doesn\'t match value count at row', MYSQL),
    (r'mysql_fetch_array()', MYSQL),
    (r'mysql_', MYSQL),
    (r'on MySQL result index', MYSQL),
    (r'You have an error in your SQL syntax;', MYSQL),
    (r'You have an error in your SQL syntax near', MYSQL),
    (r'MySQL server version for the right syntax to use', MYSQL),
    (r'Division by zero in', MYSQL),
    (r'not a valid MySQL result', MYSQL),
    (r'[MySQL][ODBC', MYSQL),
    (r"Column count doesn't match", MYSQL),
    (r"the used select statements have different number of columns",
        MYSQL),
    (r"DBD::mysql::st execute failed", MYSQL),
    (r"DBD::mysql::db do failed:", MYSQL),

    # SQLite
    (r'could not prepare statement', SQLITE),

    # Generic errors..
    (r'Unknown column', UNKNOWN),
    (r'where clause', UNKNOWN),
    (r'SqlServer', UNKNOWN),
    (r'syntax error', UNKNOWN),
    (r'Microsoft OLE DB Provider', UNKNOWN),
    )


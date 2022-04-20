NORMAL_USER = 1
ADMINISTRATOR = 2
SUPER_ADMIN = 3

def connect_to_db(name, rootDir="db")
    db = SQLite3::Database.new("#{rootDir}/#{name}.db")
    db.results_as_hash = true
    return db
end

def get_field(db_name, table, field, id, rootDir="db")
    db = connect_to_db(db_name)
    return db.execute("SELECT #{field} FROM #{table} WHERE id = ?", [id]).first[field]
end
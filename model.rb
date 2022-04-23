NORMAL_USER = 1
ADMIN = 2
SUPER_ADMIN = 3

def string_is_int(str)
    return str.to_i.to_s == str
end

def connect_to_db(name, rootDir="db")
    db = SQLite3::Database.new("#{rootDir}/#{name}.db")
    db.results_as_hash = true
    return db
end

def get_field(db_name, table, field, id, rootDir="db")
    db = connect_to_db(db_name)
    # You can't use ? on fields and tables
    puts("SELECT #{field} FROM #{table} WHERE id = #{id}")
    return db.execute("SELECT #{field} FROM #{table} WHERE id = ?", [id]).first[field]
end

def match_path(path,paths)
    for testPath in paths
        if path == testPath || path == "/#{testPath}"
            return true
        end
    end

    return false
end

def is_super_admin(user_id)
    if user_id == nil
        return false
    end

    permission_level = get_field("database", "users", "permission_level", session[:user_id]).to_i

    return permission_level >= SUPER_ADMIN
end
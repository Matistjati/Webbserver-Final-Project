NORMAL_USER = 1
ADMIN = 2
SUPER_ADMIN = 3
LOGIN_COOLDOWN = 3

def string_is_int(str)
    return str.to_i.to_s == str
end

def connect_to_db(name, rootDir="db")
    db = SQLite3::Database.new("#{rootDir}/#{name}.db")
    db.results_as_hash = true
    return db
end

def get_field(table, field, id, db_name="database", rootDir="db")
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

def is_admin(user_id)
    if user_id == nil
        return false
    end

    permission_level = get_field("users", "permission_level", session[:user_id]).to_i

    return permission_level >= ADMIN
end

def is_super_admin(user_id)
    if user_id == nil
        return false
    end

    permission_level = get_field("users", "permission_level", session[:user_id]).to_i

    return permission_level >= SUPER_ADMIN
end

def get_fields(fields, table, field_where, value, database="database")
    db = connect_to_db(database)
    return db.execute("SELECT #{fields} FROM #{table} where #{field_where} = ?", [value])
end

def get_all_fields(fields, table, database="database")
    db = connect_to_db(database)
    return db.execute("SELECT #{fields} FROM #{table}")
end

def insert_into(fields, table, values, database="database")
    db = connect_to_db(database)

    # Generate (?,?)
    question_tuple = "("
    for value in values
        question_tuple += "?,"
    end
    question_tuple = question_tuple[0...-1]
    question_tuple += ")"

    print("INSERT INTO #{table}(#{fields}) VALUES #{question_tuple}")
    db.execute("INSERT INTO #{table}(#{fields}) VALUES #{question_tuple}", values)
end

def too_long(data, max_length = 100)
    return data.length > max_length
end

def get_post_tags(post_id, database="database")
    db = connect_to_db(database)
    return db.execute("SELECT tag_name FROM tags INNER JOIN tag_post_relations rel WHERE tags.id = rel.tag_id AND rel.post_id=?", [post_id])
end

def delete_where(table, field, value, database="database")
    db = connect_to_db(database)
    db.execute("DELETE FROM #{table} WHERE #{field} = ?", value)
end

def get_all(table, database="database")
    db = connect_to_db(database)
    return db.execute("SELECT * FROM #{table}")
end

def update_table(table, field, value, id, database="database")
    db = connect_to_db(database)
    db.execute("UPDATE #{table} SET #{field}=? WHERE id=?", [value, id])
end

def get_all_table_names(database="database")
    db = connect_to_db(database)
    return db.execute("SELECT name FROM sqlite_master WHERE type='table';")
end

def unsafe_insertion(table, values, database="database")
    db = connect_to_db(database)
    db.execute("INSERT INTO #{table} VALUES #{values}")
end

def delete_nth_row(table, row, database="database")
    db = connect_to_db(database)
    db.execute("DELETE FROM #{table} WHERE id in (SELECT id FROM #{table} LIMIT 1 OFFSET #{row})")
end

def can_log_in()
    d = Time.now.to_i

    if session[:last_login_attempt] == nil
        session[:last_login_attempt] = d
        return true
    else
        if d-session[:last_login_attempt].to_i > LOGIN_COOLDOWN
            session[:last_login_attempt] = d
            return true
        else
            return false
        end
    end
end

def user_ok(username, password, password_confirm)
    if too_long(username) or too_long(password)
        session[:error] = "Too long"
        return false
    end

    # Password don't match
    if password != password_confirm
        session[:error] = "Passwords do not match"
        session[:filled_username] = username
        return false
    end

    if not can_log_in()
        session[:error] = "Wait a few seconds"
        return false
    end

    # Don't allow empty usernames/passwords
    if username.strip() == "" || password.strip() == ""
        session[:error] = "Empty " + (username.strip() == "" ? "username" : "password")
        session[:filled_username] = username
        return false
    end

    return true
end
require 'sinatra'
require 'slim'
require 'sqlite3'
require 'bcrypt'
require_relative 'common.rb'

enable :sessions

before("/*") do |path|
    # If you are already logged in, you can't register or login
    if session[:user_id] != nil and (path=="users/login" or path=="users/register")
        redirect("/index")
    end

end

get("/") do
    redirect("/index")
end

get("/index") do
    puts("ligma")

    username = nil
    if session[:user_id] != nil
        username = get_field("database", "users", "username", session[:user_id])
    end

    slim(:index, locals:{"username": username})
end

get("/users/login") do
    login_error = session[:login_error_message]
    session[:login_error_message] = nil
    filled_username = session[:filled_username]
    session[:filled_username] = nil

    slim(:"users/login", locals:{"error":login_error, "filled_username": filled_username})
end

post("/users/validate") do
    username = params["username"]
    password = params["password"]

    db = connect_to_db("database")

    result = db.execute("SELECT id, password_digest FROM users WHERE username = ?", [username])

    if result.empty?
        session[:login_error_message] = "No user exists with that username"
        redirect("/users/login")
    else
        password_digest = BCrypt::Password.new(result.first["password_digest"])
        if password_digest == password
            session[:user_id] = result.first["id"]
            redirect("/index")
        else
            session[:login_error_message] = "Incorrect password"
            redirect("/users/login")
        end
    end

end

get("/users/register") do
    register_error = session[:register_error_message]
    session[:register_error_message] = nil
    filled_username = session[:filled_username]
    session[:filled_username] = nil


    puts("ligma")

    slim(:"users/register", locals:{"error":register_error, "filled_username": filled_username})
end

get("/users/logout") do
    session[:user_id] = nil

    redirect("/index")
end

post("/users/new") do
    username = params["username"]
    password = params["password"]
    password_confirmation = params["password_confirm"]

    if password != password_confirmation
        session[:register_error_message] = "Passwords do not match"
        session[:filled_username] = username
        redirect("users/register")
    end

    db = connect_to_db("database")

    result = db.execute("SELECT id from users WHERE username=?", username)

    if result.empty?
        password_digest = BCrypt::Password.create(password)
        db.execute("INSERT INTO users(username, password_digest, permission_level) VALUES (?,?,1)", [username, password_digest])
        session[:user_id] = db.execute("SELECT id from users WHERE username = ?", [username]).first["id"]
        redirect("../index")
    else
        session[:register_error_message] = "Username already exists"
        redirect("users/register")
    end


end

get("/debug") do
    # Get all tables
    #session[:debug_table_selected] = "users"
    selected_table = session[:debug_table_selected]

    db = connect_to_db("database")

    table = nil
    if selected_table != nil
        # If table is selected, get its data
        table = db.execute("SELECT * FROM #{selected_table}")
    end

    # Get names of tables
    tables = db.execute("SELECT name FROM sqlite_master WHERE type='table';")


    slim(:"debug", locals:{"tables":tables, "selected": selected_table, "viewed_table": table})
end


post("/select_db") do
    session[:debug_table_selected] = params[:selected_db]

    redirect("/debug")
end

post("/add_row") do
    value = "("
    for field in params do
        value += "\"" + field[1] + "\""
        value += ","
    end

    value = value[0...-1]

    value += ")"

    db = connect_to_db("database")
    puts("INSERT INTO #{session[:debug_table_selected]} VALUES #{value}")
    db.execute("INSERT INTO #{session[:debug_table_selected]} VALUES #{value}")


    redirect("/debug")
end

post("/delete_row") do 
    row = params[:row].to_i

    db = connect_to_db("database")
    
    db.execute("DELETE FROM #{session[:debug_table_selected]} WHERE id in (SELECT id FROM #{session[:debug_table_selected]} LIMIT 1 OFFSET #{row})")

    redirect("/debug")
end
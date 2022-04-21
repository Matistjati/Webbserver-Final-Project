require 'sinatra'
require 'slim'
require 'sqlite3'
require 'bcrypt'
require_relative 'model.rb'

enable :sessions



before do
    path = request.path_info

    permission_level = 0
    if session[:user_id] != nil
        permission_level = get_field("database", "users", "permission_level", session[:user_id]).to_i
    end

    # Super admin has access to everything
    if permission_level >= SUPER_ADMIN
        return
    end

    # If you are already logged in, you can't register or login
    if session[:user_id] != nil && match_path(path, ["users/login", "users/register", "users/validate","users/new"])
        redirect("/error/401")
    end

    
    puts(path)
    # Only allow super admins to access debug
    if match_path(path, ["debug","add_row","delete_row","select_db"])
        redirect("/error/401")
    end

    # 401, can't create problem anonymously
    puts(path)
    if session[:user_id] == nil && match_path(path, ["problems/new", "problems"])
        redirect("/error/401")
    end
end

before("/problems/:id/*") do
    if session[:user_id] == nil
        redirect("error/401")
    end

    if string_is_int(params["id"]) && get_field("database", "posts", "author_id", params["id"].to_i).to_i != session[:user_id]
        redirect("error/401")
    end
end


get("/error/:id") do
    errors = 
    {
        404 => "Page does not exist",
        401 => "Unauthorized access",
        500 => "Internal server error"
    }

    if errors.has_key?(params[:id].to_i)
        error_id = params[:id].to_i.to_s == params[:id] ? params[:id].to_i : 404
    else
        redirect("/errors/404")
    end

    puts(error_id)
    puts(errors[error_id])
    slim(:error, locals:{"error_message": errors[error_id], "error_id": error_id})
end

get("/") do
    username = nil
    permission_level = 0
    if session[:user_id] != nil
        username = get_field("database", "users", "username", session[:user_id])
        permission_level = get_field("database", "users", "permission_level", session[:user_id]).to_i
    end

    slim(:index, locals:{"username": username, "permission_level": permission_level})
end

get("/problems/") do

    db = connect_to_db("database")
    problems = db.execute("SELECT id, author_id, post_name FROM posts")

    permission_level = 0

    if session[:user_id] != nil
        permission_level = get_field("database", "users", "permission_level", session[:user_id])
    end

    slim(:"problems/index", locals:{"problems":problems, "user_id": session[:user_id], "permission_level": permission_level})
end

get("/problems/new") do

    error = session[:error]
    session[:error] = nil

    slim(:"problems/new", locals:{"error": error})
end

post("/problems") do
    if session[:user_id] == nil
        redirect("error/401")
    end

    post_name = params["name"]

    db = connect_to_db("database")

    result = db.execute("SELECT post_name FROM posts where post_name = ?", post_name)

    if result.empty?
        db.execute("INSERT INTO posts(content_path, post_name, author_id) VALUES (?,?,?)", ["public/problems/#{post_name}.txt",post_name,session[:user_id]])
        
        post_id = db.execute("SELECT id FROM posts WHERE author_id = ?", [session[:user_id]]).last["id"]
        # Create an empty file for the post
        File.open("public/problems/#{post_name}.txt", "w") {}
        redirect("/problems/#{post_id}/edit")
    else
        session[:error] = "Another post named #{post_name} already exists"
        redirect("/problems/new")
    end

end

get("/problems/:id") do
    db = connect_to_db("database")

    post_info = db.execute("SELECT content_path, post_name, author_id FROM posts WHERE id = ?", [params[:id]]).first

    content = File.read(post_info["content_path"])

    slim(:"problems/show", locals:{"name":post_info["post_name"], "content": content})
end

get("/problems/:id/edit") do    
    if session[:user_id] == nil || !string_is_int(params["id"])
        return
    end

    db = connect_to_db("database")

    post_info = db.execute("SELECT content_path, post_name, author_id FROM posts WHERE id = ?", [params[:id]]).first

    
    # If not author, do not allow
    # If admin, do allow
    if post_info["author_id"].to_i != session[:user_id] and get_field("database", "users", "permission_level", session[:user_id]).to_i < ADMIN
        redirect("/error/401")
    end

    # If the file somehow doesn't exist, cry about it
    if not File.exist?(post_info["content_path"]) 
        redirect("/error/500")
    end
    content = File.read(post_info["content_path"])

    info_message = session[:info_message]
    session[:info_message] = nil


    slim(:"problems/edit", locals:{"name":post_info["post_name"], "content": content, "info_message": info_message})
end

post("/problems/:id/delete") do
    if session[:user_id] == nil || !string_is_int(params["id"])
        return
    end

    db = connect_to_db("database")

    post_info = db.execute("SELECT content_path, post_name, author_id FROM posts WHERE id = ?", [params[:id]]).first

    

    # If not author, do not allow
    # If super admin, do allow (normal admins shouldn't be able to delete)
    if post_info["author_id"].to_i != session[:user_id] and get_field("database", "users", "permission_level", session[:user_id]).to_i < SUPER_ADMIN
        redirect("/error/401")
    end

    if File.exist?(post_info["content_path"]) 
        File.delete(post_info["content_path"])
    end


    db.execute("DELETE FROM posts WHERE id = ?", params[:id])

    redirect("/problems/")
end

post("/problems/:id/update") do
    if session[:user_id] == nil || !string_is_int(params["id"])
        return
    end


    db = connect_to_db("database")

    post_info = db.execute("SELECT content_path, post_name, author_id FROM posts WHERE id = ?", [params[:id]]).first


    # If not author, do not allow
    # If admin, do allow
    if post_info["author_id"].to_i != session[:user_id] and get_field("database", "users", "permission_level", session[:user_id]).to_i < ADMIN
        redirect("/error/401")
    end


    # If the file somehow doesn't exist, cry about it
    if not File.exist?(post_info["content_path"]) 
        redirect("/error/500")
    end
    File.open(post_info["content_path"], "w") { |file| file.write(params["content"])}

    session[:info_message] = "Saved!"

    redirect("/problems/#{params[:id]}/edit")
end

get("/users/login") do
    login_error = session[:error]
    session[:error] = nil
    filled_username = session[:filled_username]
    session[:filled_username] = nil

    slim(:"users/login", locals:{"error":login_error, "filled_username": filled_username})
end

post("/users/login") do
    username = params["username"]
    password = params["password"]

    db = connect_to_db("database")

    result = db.execute("SELECT id, password_digest FROM users WHERE username = ?", [username])

    if result.empty?
        session[:error] = "No user exists with that username"
        redirect("/users/login")
    else
        password_digest = BCrypt::Password.new(result.first["password_digest"])
        if password_digest == password
            session[:user_id] = result.first["id"]
            redirect("/")
        else
            session[:error] = "Incorrect password"
            redirect("/users/login")
        end
    end

end

get("/users/register") do
    register_error = session[:error]
    session[:error] = nil
    filled_username = session[:filled_username]
    session[:filled_username] = nil

    slim(:"users/register", locals:{"error":register_error, "filled_username": filled_username})
end

get("/users/logout") do
    session[:user_id] = nil

    redirect("/")
end

post("/users/new") do
    username = params["username"]
    password = params["password"]
    password_confirmation = params["password_confirm"]

    # Password don't match
    if password != password_confirmation
        session[:error] = "Passwords do not match"
        session[:filled_username] = username
        redirect("users/register")
    end

    # Don't allow empty usernames/passwords
    if username.strip() == "" || password.strip() == ""
        session[:error] = "Empty " + (username.strip() == "" ? "username" : "password")
        session[:filled_username] = username
        redirect("users/register")
    end


    db = connect_to_db("database")

    result = db.execute("SELECT id from users WHERE username=?", username)

    if result.empty?
        password_digest = BCrypt::Password.create(password)
        db.execute("INSERT INTO users(username, password_digest, permission_level) VALUES (?,?,#{NORMAL_USER})", [username, password_digest])
        session[:user_id] = db.execute("SELECT id from users WHERE username = ?", [username]).first["id"]
        redirect("../index")
    else
        session[:error] = "Username already exists"
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
        v = field[1]
        # Allow admin to create users
        
        if field[0] == "password_digest"
            v = BCrypt::Password.create(v)
        end
        value += "\"" + v + "\""
        value += ","
    end

    value = value[0...-1]

    value += ")"

    db = connect_to_db("database")
    db.execute("INSERT INTO #{session[:debug_table_selected]} VALUES #{value}")


    redirect("/debug")
end

post("/delete_row") do 
    row = params[:row].to_i

    db = connect_to_db("database")
    
    db.execute("DELETE FROM #{session[:debug_table_selected]} WHERE id in (SELECT id FROM #{session[:debug_table_selected]} LIMIT 1 OFFSET #{row})")

    redirect("/debug")
end

not_found do
    redirect("/error/404")
end
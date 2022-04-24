require 'sinatra'
require 'slim'
require 'sqlite3'
require 'bcrypt'
require 'set'
require_relative 'model.rb'


enable :sessions


before do
    path = request.path_info
    
    permission_level = 0
    if session[:user_id] != nil
        permission_level = get_field("users", "permission_level", session[:user_id]).to_i
    end

    # Super admin has access to everything
    if is_super_admin(session[:user_id])
        return
    end

    # If you are already logged in, you can't register or login
    if session[:user_id] != nil && match_path(path, ["users/login", "users/new", "users/validate","users/new"])
        redirect("/error/401")
    end

    
    # Only allow super admins to access debug
    if match_path(path, ["debug","add_row","delete_row","select_db"])
        redirect("/error/401")
    end

    # 401, can't create problem anonymously
    if session[:user_id] == nil && match_path(path, ["problems/new", "problems"])
        redirect("/error/401")
    end
end

before("/problems/:id/*") do
    if session[:user_id] == nil || !string_is_int(params["id"])
        redirect("/error/401")
    end

    if is_super_admin(session[:user_id])
        return
    end


    if string_is_int(params["id"]) and not get_fields("author_id", "posts", "id", params["id"]).empty? and get_fields("author_id", "posts", "id", params["id"]).first["author_id"] != session[:user_id]
        redirect("/error/401")
    end
end

before("/tags/:id/*") do
    if session[:user_id] == nil || !string_is_int(params["id"])
        redirect("/error/401")
    end

    if is_super_admin(session[:user_id])
        return
    end

    if string_is_int(params["id"]) and not get_field("tags", "author_id", params["id"].to_i).empty? and get_field("tags", "author_id", params["id"].to_i).first["author_id"] != session[:user_id]
        redirect("/error/401")
    end
end

get("/") do
    username = nil
    permission_level = 0
    if session[:user_id] != nil
        username = get_field("users", "username", session[:user_id])
        permission_level = get_field("users", "permission_level", session[:user_id]).to_i
    end

    slim(:index, locals:{"username": username, "permission_level": permission_level, "id": session[:user_id]})
end

get("/error/:id") do
    errors = 
    {
        404 => "Page does not exist",
        401 => "Unauthorized access",
        500 => "Internal server error"
    }

    if errors.has_key?(params[:id].to_i)
        # If unknown error, default to 404
        error_id = params[:id].to_i.to_s == params[:id] ? params[:id].to_i : 404
    else
        redirect("/errors/404")
    end

    slim(:error, locals:{"error_message": errors[error_id], "error_id": error_id})
end

get("/tags/") do

    tags = get_all_fields("id, author_id, tag_name", "tags")

    permission_level = 0

    if session[:user_id] != nil
        permission_level = get_field("users", "permission_level", session[:user_id])
    end

    error = session[:error]
    session[:error] = nil

    slim(:"tags/index", locals:{"tags":tags, "user_id": session[:user_id], "permission_level": permission_level, "error": error})
end

post("/tags") do
    if session[:user_id] == nil
        redirect("/error/401")
    end

    if too_long(params["tag_name"])
        redirect("/error/500")
    end

    tag_name = params["tag_name"]

    exists = get_fields("tag_name", "tags", "tag_name", params["tag_name"])

    # Does the tag already exist
    if exists.empty?
        insert_into("tag_name, author_id", "tags", [tag_name,session[:user_id]])
    
        redirect("/tags/")
    else
        session[:error] = "Another tag named #{tag_name} already exists"
        redirect("/tags/")
    end
end

post("/tags/:id/delete") do
    if session[:user_id] == nil || !string_is_int(params["id"])
        redirect("/error/401")
    end

    post_info = get_fields("id, tag_name, author_id", "tags", "id", params[:id]).first

    # If not author, do not allow
    # If super admin, do allow (normal admins shouldn't be able to delete)
    if not is_super_admin(session[:user_id]) and (post_info == nil or post_info["author_id"].to_i != session[:user_id])
        redirect("/error/401")
    end

    delete_where("tags", "id", params[:id])
    delete_where("tag_post_relations", "tag_id", params[:id])

    redirect("/tags/")
end

get("/problems/") do
    permission_level = 0

    if session[:user_id] != nil
        permission_level = get_field("users", "permission_level", session[:user_id])
    end

    problems = get_all_fields("id, author_id, post_name", "posts")

    finalProblems = []
    for problem in problems
        # Get all tags
        
        tags = get_post_tags(problem["id"])

        problem["tags"] = Set[]
        problem["author_name"] = get_field("users", "username", problem["author_id"])

        for tag in tags
            problem["tags"].add(tag["tag_name"])
        end

        # Filter problems if we have a tag based filter
        if session[:tag_query] != nil and session[:tag_query].length > 0 and session[:query_type] != nil
            matching = []
            for tag in session[:tag_query]
                matching.push(problem["tags"].include?(tag))
            end

            
            if session[:query_type] == "and"
                if matching.all?
                    finalProblems.push(problem)
                end
            else # Default to or
                if matching.any?
                    finalProblems.push(problem)
                end
            end
        else
            finalProblems.push(problem)
        end
    end

    slim(:"problems/index", locals:{"problems":finalProblems, "user_id": session[:user_id], "permission_level": permission_level, "tag_query": session[:tag_query], "query_type": session[:query_type]})
end

post("/problems/update_filter") do
    if too_long(params["query"], 500) or too_long(params["query_type"]) # List of tags might be long in practice
        redirect("/error/500")
    end

    tags = params["query"]
    tags = tags.split(",")
    tags = tags.collect(&:strip)
    
    session[:tag_query] = tags
    session[:query_type] = params["query_type"]
    redirect("/problems/")
end

get("/problems/new") do

    error = session[:error]
    session[:error] = nil

    slim(:"problems/new", locals:{"error": error})
end

post("/problems") do
    if session[:user_id] == nil
        redirect("/error/401")
    end

    if too_long(params["name"])
        redirect("/error/500")
    end

    post_name = params["name"]


    result = get_fields("post_name", "posts", "post_name", post_name)

    if result.empty?
        insert_into("content_path, post_name, author_id", "posts", ["public/problems/#{post_name}.txt",post_name,session[:user_id]])
        
        post_id = get_fields("id", "posts", "post_name", post_name).last["id"]
        # Create an empty file for the post
        File.open("public/problems/#{post_name}.txt", "w") {}
        redirect("/problems/#{post_id}/edit")
    else
        session[:error] = "Another post named #{post_name} already exists"
        redirect("/problems/new")
    end

end

get("/problems/:id") do
    post_info = get_fields("content_path, post_name, author_id", "posts", "id", params[:id]).first
    tags = get_post_tags(params[:id])
    author_name = get_field("users", "username", post_info["author_id"])

    content = File.read(post_info["content_path"])

    slim(:"problems/show", locals:{"name":post_info["post_name"], "content": content, "tags": tags, "author_name": author_name})
end

get("/problems/:id/edit") do    
    if session[:user_id] == nil || !string_is_int(params["id"])
        redirect("/error/401")
    end

    post_info = get_fields("content_path, post_name, author_id", "posts", "id", params[:id]).first

    
    # If not author, do not allow
    # If admin, do allow
    if not is_admin(session[:user_id]) and (post_info == nil or post_info["author_id"].to_i != session[:user_id])
        redirect("/error/401")
    end

    # If the file somehow doesn't exist, cry about it
    if not File.exist?(post_info["content_path"]) 
        redirect("/error/500")
    end
    content = File.read(post_info["content_path"])

    info_message = session[:info_message]
    session[:info_message] = nil

    tags = get_post_tags(params["id"])

    sortedTags = []
    for tag in tags do
        sortedTags.push(tag[0])
    end
    sortedTags = sortedTags.sort()

    slim(:"problems/edit", locals:{"name":post_info["post_name"], "content": content, "info_message": info_message, "tags":sortedTags})
end

post("/problems/:id/delete") do
    if session[:user_id] == nil || !string_is_int(params["id"])
        redirect("/error/401")
    end

    post_info = get_fields("content_path, post_name, author_id", "posts", "id", params[:id]).first

    # If not author, do not allow
    # If super admin, do allow (normal admins shouldn't be able to delete)
    if not is_super_admin(session[:user_id]) and (post_info == nil or post_info["author_id"].to_i != session[:user_id])
        redirect("/error/401")
    end


    if File.exist?(post_info["content_path"]) 
        File.delete(post_info["content_path"])
    end


    delete_where("posts", "id", params[:id])
    delete_where("tag_post_relations", "post_id", params[:id])

    redirect("/problems/")
end

post("/problems/:id/update") do
    if session[:user_id] == nil || !string_is_int(params["id"])
        redirect("/error/401")
    end

    if too_long(params["content"], 10000) or too_long(params["tags"], 500) # Posts and tags are allowed to be long
        redirect("/error/500")
    end

    post_info = get_fields("content_path, post_name, author_id", "posts", "id", params[:id]).first

    # If not author, do not allow
    # If admin, do allow
    if not is_admin(session[:user_id]) and (post_info == nil or post_info["author_id"].to_i != session[:user_id])
        redirect("/error/401")
    end


    # Update post content
    # If the file somehow doesn't exist, cry about it
    if not File.exist?(post_info["content_path"]) 
        redirect("/error/500")
    end
    File.open(post_info["content_path"], "w") { |file| file.write(params["content"])}

    # Update tags
    tags = params["tags"]
    tags = tags.split(",")
    tags = tags.collect(&:strip)
    
    # Get id of tags
    tag_ids = []
    for tag in tags
        result = get_fields("id", "tags", "tag_name", tag)
        if result.length > 0
            tag_ids.push(result.first["id"])
        end
    end

    # Remove old tags
    delete_where("tag_post_relations", "post_id", params["id"])
    
    # Add new tags
    for tag in tag_ids
        insert_into("post_id, tag_id", "tag_post_relations",  [params["id"].to_i, tag])
    end

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
    if not can_log_in()
        session[:error] = "Wait a moment before trying again"
        redirect("/users/login")
    end

    username = params["username"]
    password = params["password"]

    if too_long(username) or too_long(password)
        redirect("/error/500")
    end

    result = get_fields("id, password_digest", "users", "username", username)

    if result.empty?
        # Don't give away too much info
        session[:error] = "Failed login"
        redirect("/users/login")
    else
        password_digest = BCrypt::Password.new(result.first["password_digest"])
        if password_digest == password
            session[:user_id] = result.first["id"]
            redirect("/")
        else
            # Don't give away too much info
            session[:error] = "Failed login"
            redirect("/users/login")
        end
    end
end

get("/users/new") do
    register_error = session[:error]
    session[:error] = nil
    filled_username = session[:filled_username]
    session[:filled_username] = nil

    slim(:"users/new", locals:{"error":register_error, "filled_username": filled_username})
end

get("/users/logout") do
    session.destroy()

    redirect("/")
end

get("/users/:id/edit") do
    if session[:user_id] == nil || !string_is_int(params["id"]) || params["id"].to_i != session[:user_id]
        redirect("/error/401")
    end

    username = get_field("users", "username", session[:user_id])

    error = session[:error]
    session[:error] = nil

    slim(:"users/edit", locals:{"username": username, "error": error, "id": session[:user_id]})
end

post("/users/:id/update") do
    if session[:user_id] == nil || !string_is_int(params["id"]) || params["id"].to_i != session[:user_id]
        redirect("/error/401")
    end

    if not can_log_in()
        session[:error] = "Wait a few seconds"
        redirect("/users/#{params[:id]}/edit")
    end

    username = params["username"]
    password = params["password"]
    password_confirmation = params["password_confirm"]

    if too_long(username) or too_long(password)
        session[:error] = "Too long"
        redirect("/users/#{params[:id]}/edit")
    end

    if not is_password_strong?(password)
        session[:error] = "Password too weak. Must include 1 lowercase, uppercase, number and special character and be atleast 8 long"
        session[:filled_username] = username
        redirect("/users/#{params[:id]}/edit")
    end

    match = get_fields("username", "users", "username", username)
    if match.empty?
        if username.strip() == ""
            session[:error] = "Empty username"
            redirect("/users/#{params[:id]}/edit")
        end
        update_table("users", "username", username, session[:user_id])
        session[:error] = "Updated username"
    else
        session[:error] = "Username taken"
        redirect("/users/#{params[:id]}/edit")
    end
    
    if password.strip() != ""
        if password != password_confirmation
            session[:error] = "Passwords do not match"
            session[:filled_username] = username
            return false
        end

        password_digest = BCrypt::Password.create(password)
        update_table("users", "password_digest", password_digest, session[:user_id])
        session[:error] += (session[:error].length == 0 ? "Updated password" : " and password")
    end

    redirect("/users/#{params[:id]}/edit")
end


post("/users/:id/delete") do
    if session[:user_id] == nil || !string_is_int(params["id"]) || params["id"].to_i != session[:user_id]
        redirect("/error/401")
    end

    delete_where("users", "id", session[:user_id])
    # Cascading deletions
    
    delete_tag_relations(session[:user_id])
    delete_where("tags", "author_id", session[:user_id])

    posts = get_fields("id, content_path", "posts", "author_id", session[:user_id])
    for post in posts
        delete_where("tag_post_relations", "post_id", post["id"])
        if File.exist?(post["content_path"]) 
            File.delete(post["content_path"])
        end
    end
    delete_where("posts", "author_id", session[:user_id])

    session.destroy()
    redirect("/")
end

post("/users") do
    username = params["username"]
    password = params["password"]
    password_confirmation = params["password_confirm"]

    if not user_ok(username, password, password_confirmation)
        redirect("/users/new")
    end

    result = get_fields("id", "users", "username", username)

    if result.empty?
        password_digest = BCrypt::Password.create(password)
        insert_into("username, password_digest, permission_level", "users", [username, password_digest, NORMAL_USER])
        session[:user_id] = get_fields("id", "users", "username", username).first["id"]
        redirect("/")
    else
        session[:error] = "Username already exists"
        redirect("users/new")
    end


end

get("/debug") do
    # Get all tables
    #session[:debug_table_selected] = "users"
    selected_table = session[:debug_table_selected]

    table = nil
    if selected_table != nil
        # If table is selected, get its data
        table = get_all(selected_table)
    end

    # Get names of tables
    tables = get_all_table_names()

    slim(:"debug", locals:{"tables":tables, "selected": selected_table, "viewed_table": table})
end

post("/select_db") do
    if params[:select_db] != nil and too_long(params[:select_db])
        redirect("/error/500")
    end
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

    insert_into(session[:debug_table_selected], value)

    redirect("/debug")
end

post("/delete_row") do 
    row = params[:row].to_i
    
    delete_nth_row(session[:debug_table_selected], row)

    redirect("/debug")
end

not_found do
    redirect("/error/404")
end
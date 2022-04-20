require 'sinatra'
require 'slim'
require 'sqlite3'
require 'bcrypt'
require_relative 'common.rb'

enable :sessions




get("/") do
    puts("ligma")
    slim(:index)
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


    slim(:debug, locals:{"tables":tables, "selected": selected_table, "viewed_table": table})
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
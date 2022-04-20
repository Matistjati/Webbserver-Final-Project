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

get("/debug_view") do
    # Get all tables
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

    redirect("/debug_view")
end
# All model functions
module Model
    # Different permission levels for users
    # Normal users has basic acces
    NORMAL_USER = 1
    # Admins can edit other profiles and posts
    ADMIN = 2
    # Super admins can edit the database and delete other users, their tags and posts
    SUPER_ADMIN = 3
    # The number of seconds one must wait between attempting a login
    LOGIN_COOLDOWN = 3

    # Checks whether we can safely call to_i on a string without getting unexpected results
    #
    # @param [String] str The string containing a presumed integer
    #
    # @return [Boolean] Whether we can call to_i on the string without weird behavior
    def string_is_int(str)
        return str.to_i.to_s == str
    end

    # Creates a connection to a database
    #
    # @param [String] name The file name of the database (without .db)
    # @param [String] rootDir The root directory where all databases are stored
    #
    # @return [Database] The object representing the database
    def connect_to_db(name, rootDir="db")
        db = SQLite3::Database.new("#{rootDir}/#{name}.db")
        db.results_as_hash = true
        return db
    end

    # Checks whether a path is included within an array of different paths
    #
    # @param [String] path The path to check
    # @param [String] paths The paths we want to check path agaisnt
    #
    # @return [Boolean] Whether the path matches one of the paths
    def match_path(path,paths)
        for testPath in paths
            if path == testPath || path == "/#{testPath}"
                return true
            end
        end

        return false
    end


    # Checks whether a password is string enough using a regex
    #
    # @param [String] password The password to check
    #
    # @return [Boolean] Whether the password matches the regex. True=strong password
    def is_password_strong?(password)
        # ^ start
        # (?=.*[A-Z]) Atleast one uppercase character
        # (?=.*[a-z]) Atleast one lowercase character
        # (?=.*[0-9]) Atleast one number
        # (?=.*[!@#$%^&*_]) Atleast one special character
        # (?=.{8,}) Atleast 8 long
        return password.match(/^(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*[!@#$%^&*_])(?=.{8,})/)
    end

    # Checks whether a string is too long
    #
    # @param [String] data The data to validate the length of
    # @param [Integer] max_length How long the string can be at most
    #
    # @return [Boolean] Whether the string is too long based on max_length
    def too_long(data, max_length = 100)
        return data.length > max_length
    end

    # Hash a string using the BCrypt algorithm
    #
    # @param [String] password The string to hash
    #
    # @return [String] The digest of the data
    def hash_password(password)
        return BCrypt::Password.create(password)
    end

    # Check whether a password matches a digest
    #
    # @param [String] digest The digest to check
    # @param [String] password The password to hash
    #
    # @return [Boolean] Whether the password matches the digest
    def passwords_match(digest, password)
        password_checker = BCrypt::Password.new(digest)
        return password_checker == password
    end

    # Get the first matching field from a table
    #
    # @param [String] table The name of the table to select from
    # @param [String] field The field we want to select
    # @param [Integer] id The id of the row we want to select
    # @param [String] db_name The database we want to select from
    # @param [String] rootDir The root directory of the database
    #
    # @return [String] The field matching the id
    def get_field(table, field, id, db_name="database", rootDir="db")
        db = connect_to_db(db_name)
        # You can't use ? on fields and tables
        return db.execute("SELECT #{field} FROM #{table} WHERE id = ?", [id]).first[field]
    end

    # Get all fields matching single-expression WHERE clause
    #
    # @param [String] fields The fields we want to select
    # @param [String] table The name of the table to select from
    # @param [String] field_where The left part of the WHERE clause
    # @param [String] value The right part of the WHERE clause
    # @param [String] database The database we want to select from
    #
    # @return [Hash] All fields matching the WHERE clause
    def get_fields(fields, table, field_where, value, database="database")
        db = connect_to_db(database)
        return db.execute("SELECT #{fields} FROM #{table} WHERE #{field_where} = ?", [value])
    end

    # Get all the requested fields from a table
    #
    # @param [String] fields The fields we want to select
    # @param [String] table The name of the table to select from
    # @param [String] database The database we want to select from
    #
    # @return [Hash] All fields present in the parameter fields
    def get_all_fields(fields, table, database="database")
        db = connect_to_db(database)
        return db.execute("SELECT #{fields} FROM #{table}")
    end

    # Insert a row into a table
    #
    # @param [String] fields The fields we want to explicitly give
    # @param [String] table The name of the table to select from
    # @param [Array] values An array of the values of each string we explicitly want to give
    # @param [String] database The database we want to insert into
    #
    def insert_into(fields, table, values, database="database")
        db = connect_to_db(database)

        # Generate (?,?)
        question_tuple = "("
        for value in values
            question_tuple += "?,"
        end
        question_tuple = question_tuple[0...-1]
        question_tuple += ")"

        db.execute("INSERT INTO #{table}(#{fields}) VALUES #{question_tuple}", values)
    end

    
    # Get all the tags related to a specific post
    #
    # @param [String] post_id The id of the post
    # @param [String] database The database we want to select from
    #
    # @return [Hash] All the tags of the post
    def get_post_tags(post_id, database="database")
        db = connect_to_db(database)
        return db.execute("SELECT tag_name FROM tags INNER JOIN tag_post_relations rel WHERE tags.id = rel.tag_id AND rel.post_id=?", [post_id])
    end

    # Delete from a table given a single-expression WHERE clause
    #
    # @param [String] table The name of the table to delete from
    # @param [String] field The field we want to delete based on the WHERE clause
    # @param [String] value The value that the field has to match
    # @param [String] database The database we want to delete from
    #
    def delete_where(table, field, value, database="database")
        db = connect_to_db(database)
        db.execute("DELETE FROM #{table} WHERE #{field} = ?", value)
    end

    # Get all fields from a table
    #
    # @param [String] table The name of the table to select from
    # @param [String] database The database we want to select from
    #
    # @return [Hash] All fields in the table
    def get_all(table, database="database")
        db = connect_to_db(database)
        return db.execute("SELECT * FROM #{table}")
    end

    # Update a specific field in a specific row based on the id of the row
    #
    # @param [String] table The name of the table to update
    # @param [String] field The field we want to update
    # @param [String] value The value we want to set the field to
    # @param [Integer] id The id of the row we want to update
    # @param [String] database The database we want to select from
    #
    def update_table(table, field, value, id, database="database")
        db = connect_to_db(database)
        db.execute("UPDATE #{table} SET #{field}=? WHERE id=?", [value, id])
    end

    # Gets the names of all tables present in a given database
    #
    # @param [String] database The database we want to get table names from
    #
    # @return [Hash] The names of all tables
    def get_all_table_names(database="database")
        db = connect_to_db(database)
        return db.execute("SELECT name FROM sqlite_master WHERE type='table';")
    end

    # Insert a row into a table without doing any measures to prevent SQL injection. Should only be accessible by super admins
    #
    # @param [String] table The name of the table to insert into
    # @param [Array] values The values of the row to insert
    # @param [String] database The database we want to insert into
    #
    def unsafe_insertion(table, values, database="database")
        db = connect_to_db(database)
        db.execute("INSERT INTO #{table} VALUES #{values}")
    end

    # Delete the nth row in a given table
    #
    # @param [String] table The name of the table we want to delete from
    # @param [Integer] row The row we want to delete, 0-indexed
    # @param [String] database The database we want to delete from
    #
    def delete_nth_row(table, row, database="database")
        db = connect_to_db(database)
        db.execute("DELETE FROM #{table} WHERE id in (SELECT id FROM #{table} LIMIT 1 OFFSET #{row})")
    end

    # Delete all tag post relations created by a given user
    #
    # @param [Integer] author_id The user id of the user we want to delete from
    # @param [String] database The database we want to delete from
    #
    def delete_tag_relations(author_id, database="database")
        db = connect_to_db(database)

        db.execute("DELETE FROM tag_post_relations
                    WHERE tag_id IN (
                        SELECT t.id FROM tag_post_relations rel
                        INNER JOIN tags t
                        ON (t.id=rel.tag_id)
                        WHERE t.author_id = ?
                    );", author_id)
    end
end
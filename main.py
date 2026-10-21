import mysql.connector
import hashlib
import os
from dotenv import load_dotenv

load_dotenv()

def connect_db():

    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )



def create_table():
    connection = connect_db()
    cursor = connection.cursor()

    sql = """
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        hashed_password VARCHAR(128) NOT NULL,
        salt VARCHAR(128) NOT NULL,
        address VARCHAR(50) NOT NULL,
        phone_number VARCHAR(50) NOT NULL,
        department VARCHAR(50) NOT NULL,
        email VARCHAR(50) NOT NULL
    )
    """

    cursor.execute(sql)
    connection.commit()
    cursor.close()
    connection.close()



def user_exists(username):
    connection = connect_db()
    cursor = connection.cursor()

    sql = "SELECT * FROM users WHERE username = %s"
    cursor.execute(sql, (username,))

    result = cursor.fetchone()

    cursor.close()
    connection.close()

    if result is None:
        return False
    else:
        return True



def salt_hash(password):

    salt = os.urandom(16)

    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )

    return salt.hex(), hashed_password.hex()



def register_user():
    print("\n ==-- EMPLOYEE_REGISTRATION --== \n")
    user = input("Enter your username: ")

    if not user_exists(user) == True:

        password = input("Enter your password: ")
        confirm_password = input("Confirm your password: ")

        if confirm_password == password:

            salt, hashed_password = salt_hash(password)

            address = input("Enter your address: ")
            phone_number = input("Enter your phone number: ")
            department = input("Enter your department: ")
            email = input("Enter your email: ")

            connection = connect_db()
            cursor = connection.cursor()

            sql = "INSERT INTO users (username, hashed_password, salt, address, phone_number, department, email) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            data = (user, hashed_password, salt, address, phone_number, department, email)

            try:
                cursor.execute(sql, data)
                connection.commit()
                print("User Registration Successful")

            except mysql.connector.Error as error:
                print(f"Error: {error}")

            finally:
                cursor.close()
                connection.close()

    else:
        print("User already exists")



def verify_password(stored_password_hash, stored_salt_hex, provided_password):
    salt = bytes.fromhex(stored_salt_hex)

    hash_to_check = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100000
    )

    return hash_to_check.hex() == stored_password_hash



def get_employee_profile(username):

    connection = connect_db()
    cursor = connection.cursor(dictionary=True)

    sql = "SELECT * FROM users WHERE username = %s"
    cursor.execute(sql, (username,))
    profile = cursor.fetchone()

    cursor.close()
    connection.close()
    return profile



def employee_menu(username):
    while True:
        print("\n ==-- EMPLOYEE_INFO_MENU --== \n")
        print("1. VIEW FULL EMPLOYEE PROFILE")
        print("2. EXIT")

        try:

            option = int(input("Enter your option: "))

            if option == 1:
                profile = get_employee_profile(username)

                if profile:
                    print("\n" + "=" * 40)
                    print(f"Employee Profile: {profile['username'].upper()}")
                    print("-" * 40)
                    print(f"Username:     {profile['username']}")
                    print(f"E-mail:       {profile['email']}")
                    print(f"Phone number: {profile['phone_number']}")
                    print(f"Department:   {profile['department']}")
                    print(f"Address:      {profile['address']}")
                    print("=" * 40)

                else:
                    print("\nUser not Found.")

            elif option == 2:
                break

        except ValueError:
            print("\n Invalid option.")



def login():
    print("\n ==-- EMPLOYEE_LOGIN --== \n")
    user = input("Enter your username: ")

    if not user_exists(user) == False:
        password = input("Enter your password: ")

        connection = connect_db()
        cursor = connection.cursor()

        sql = "SELECT hashed_password, salt FROM users WHERE username = %s"

        cursor.execute(sql, (user,))
        result = cursor.fetchone()

        cursor.close()
        connection.close()

        if result:
            db_hashed_password, db_salt = result

            if verify_password(db_hashed_password, db_salt, password):
                print(f"\nWelcome back, {user}! Login successful.")
                employee_menu(user)
                return True
            else:
                print("\nLogin Unsuccessful, invalid credentials")

        else:
            print("\nAn error occurred while retrieving user data.")

    else:
        print("\n Username not found.")

    return False



def main_menu():
    while True:
        print("\n ==-- EMPLOYEE_SYSTEM_MENU --== \n")
        print("1. REGISTER EMPLOYEE")
        print("2. VERIFY EMPLOYEE")
        print("3. EXIT")

        option = int(input("Enter your option: "))

        try:
            if option == 1:
                register_user()
            elif option == 2:
                login()
            elif option == 3:
                break
        except ValueError:
            print("Invalid option")



if __name__ == "__main__":
    try:
        create_table()
        main_menu()

    except mysql.connector.Error as error:
        print(f"Error: {error}")
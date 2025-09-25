import db
import user_mgmt
import crypto
import getpass
import os
import sys


def safe_getpass(prompt: str) -> str:
    # Prefer hidden input when running in a real TTY and not under PyCharm hosted console
    try:
        if sys.stdin is not None and sys.stdin.isatty() and os.environ.get("PYCHARM_HOSTED") != "1":
            return getpass.getpass(prompt)
    except Exception:
        pass
    # Fallback to visible input to avoid blocking/hanging in certain IDE consoles
    try:
        return input(f"{prompt} (input visible): ")
    except EOFError:
        return ""


def main():
    print("Welcome to Password Bank!")
    while True:
        print("\n1. Log in\n2. Register new user\n3. Exit")
        choice = input("Choose an option (1-3): ")
        if choice == "1":
            username = input("Username: ")
            password = safe_getpass("Master password: ")
            if user_mgmt.authenticate_user(username, password):
                print(f"Login successful. Welcome, {username}!")
                user_session(username)
            else:
                print("Incorrect username or password.")
        elif choice == "2":
            username = input("Choose username: ")
            password = safe_getpass("Choose master password: ")
            encryption_method = choose_encryption_method()
            if user_mgmt.register_user(username, password, encryption_method):
                # If RSA is chosen at registration, create and persist keys now
                if encryption_method == "rsa" and crypto.load_rsa_keys(username) is None:
                    pub, priv = crypto.generate_rsa_keys()
                    crypto.save_rsa_keys(username, pub, priv)
                print("User registered. You can now log in.")
            else:
                print("Username is already taken.")
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice, please try again.")


def user_session(username):
    db_file = user_mgmt.get_user_db_file(username)
    db.init_db(db_file)
    user = user_mgmt.get_user(username)
    if user:
        encryption_method = user[3]
    else:
        encryption_method = "rsa"
    # Load RSA keys if needed for current user preference
    rsa_keys = crypto.load_rsa_keys(username) if encryption_method == "rsa" else None
    if encryption_method == "rsa" and rsa_keys is None:
        pub, priv = crypto.generate_rsa_keys()
        crypto.save_rsa_keys(username, pub, priv)
        rsa_keys = (pub, priv)
    while True:
        print("\n==== Password Bank ====")
        print("1. Add account")
        print("2. Show all accounts")
        print("3. View account details")
        print("4. Delete an account")
        print("5. Change encryption method")
        print("6. Log out")
        choice = input("Choose an option (1-6): ")
        if choice == "1":
            service = input("Service (e.g. Gmail): ")
            acc_username = input("Username: ")
            password = safe_getpass("Password: ")
            db.add_account(db_file, encryption_method, service, acc_username, password, rsa_keys=rsa_keys)
            print(f"Added {service} ({acc_username})")
        elif choice == "2":
            accounts = db.list_accounts(db_file)
            if not accounts:
                print("No accounts found.")
            else:
                print("\n--- Saved accounts ---")
                for acc in accounts:
                    # acc = (id, enc_service, enc_username, encryption_method)
                    row_method = acc[3]
                    keys_for_row = rsa_keys if row_method == encryption_method and row_method == 'rsa' else (crypto.load_rsa_keys(username) if row_method == 'rsa' else None)
                    try:
                        service = crypto.decrypt_password(acc[1], row_method, rsa_keys=keys_for_row)
                        acc_user = crypto.decrypt_password(acc[2], row_method, rsa_keys=keys_for_row)
                    except Exception:
                        service = "[Decryption failed]"
                        acc_user = "[Decryption failed]"
                    print(f"[{acc[0]}] {service} - {acc_user} (Encryption: {row_method})")
        elif choice == "3":
            acc_id = input("Enter the ID of the account you want to view: ")
            try:
                acc_id_int = int(acc_id)
            except ValueError:
                print("Invalid ID. Please enter a number.")
                continue
            account = db.get_account_by_id(db_file, acc_id_int)
            if account:
                # account = (id, enc_service, enc_username, enc_password, row_method)
                row_method = account[4]
                keys_for_row = rsa_keys if row_method == encryption_method and row_method == 'rsa' else (crypto.load_rsa_keys(username) if row_method == 'rsa' else None)
                try:
                    dec_service = crypto.decrypt_password(account[1], row_method, rsa_keys=keys_for_row)
                    dec_username = crypto.decrypt_password(account[2], row_method, rsa_keys=keys_for_row)
                    dec_password = crypto.decrypt_password(account[3], row_method, rsa_keys=keys_for_row)
                except Exception:
                    print("Decryption failed for this account.")
                    continue
                print("\n--- Account details ---")
                print(f"ID: {account[0]}")
                print(f"Service: {dec_service}")
                print(f"Username: {dec_username}")
                print(f"Encryption method: {row_method}")
                show_pw = input("Show password? (y/n): ").strip().lower()
                if show_pw == "y":
                    print(f"Password: {dec_password}")
                else:
                    print("Password: [hidden]")
            else:
                print("No account found with that ID.")
        elif choice == "4":
            acc_id = input("Enter the ID of the account you want to delete: ")
            try:
                acc_id_int = int(acc_id)
            except ValueError:
                print("Invalid ID. Please enter a number.")
                continue
            account_meta = db.get_account_meta_by_id(db_file, acc_id_int)
            if not account_meta:
                print("No account found with that ID.")
                continue
            # account_meta = (id, enc_service, enc_username, row_method)
            row_method = account_meta[3]
            keys_for_row = rsa_keys if row_method == encryption_method and row_method == 'rsa' else (crypto.load_rsa_keys(username) if row_method == 'rsa' else None)
            try:
                service = crypto.decrypt_password(account_meta[1], row_method, rsa_keys=keys_for_row)
                acc_user = crypto.decrypt_password(account_meta[2], row_method, rsa_keys=keys_for_row)
            except Exception:
                service = "[Decryption failed]"
                acc_user = "[Decryption failed]"
            print(f"You are about to delete the account: {service} ({acc_user})")
            confirm = input("Are you sure? (y/n): ").strip().lower()
            if confirm == "y":
                if db.delete_account_by_id(db_file, acc_id_int):
                    print("Account deleted.")
                else:
                    print("Something went wrong. Account was not deleted.")
            else:
                print("Deletion cancelled.")
        elif choice == "5":
            new_method = choose_encryption_method()
            # Update the user's encryption method in the database
            conn = user_mgmt.sqlite3.connect(user_mgmt.USERS_DB)
            cursor = conn.cursor()
            cursor.execute('UPDATE users SET encryption_method = ? WHERE username = ?', (new_method, username))
            conn.commit()
            conn.close()
            encryption_method = new_method
            # Ensure RSA keys exist if switching to RSA
            if encryption_method == "rsa" and crypto.load_rsa_keys(username) is None:
                pub, priv = crypto.generate_rsa_keys()
                crypto.save_rsa_keys(username, pub, priv)
                rsa_keys = (pub, priv)
            else:
                rsa_keys = crypto.load_rsa_keys(username) if encryption_method == "rsa" else None
            print(f"Encryption method changed to: {encryption_method}")
        elif choice == "6":
            print("Logging out...")
            break
        else:
            print("Invalid choice, please try again.")


def choose_encryption_method():
    print("\nChoose encryption method:")
    print("1. Caesar (weak)")
    print("2. Vigenère (medium)")
    print("3. RSA (strong)")
    choice = input("Choice (1-3): ")
    if choice == "1":
        method = "caesar"
    elif choice == "2":
        method = "vigenere"
    elif choice == "3":
        method = "rsa"
    else:
        print("Invalid choice, using default (rsa).")
        method = "rsa"
    return method

if __name__ == "__main__":
    main()

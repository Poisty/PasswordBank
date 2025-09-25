import random
import user_mgmt
import db
import crypto


def main():
    username = f"autotest_{random.randint(1000, 999999)}"
    master_pw = "master123"
    method = "vigenere"
    print("Username:", username)

    ok = user_mgmt.register_user(username, master_pw, method)
    if not ok:
        print("Register failed (user exists)")
        return

    db_file = user_mgmt.get_user_db_file(username)
    db.init_db(db_file)

    # Add one account
    db.add_account(db_file, method, "Gmail", "john", "p@ssw0rd", rsa_keys=None)

    # List accounts and decrypt
    rows = db.list_accounts(db_file)
    print("Rows count:", len(rows))
    for r in rows:
        rid, enc_service, enc_user, row_method = r
        service = crypto.decrypt_password(enc_service, row_method)
        user = crypto.decrypt_password(enc_user, row_method)
        print("LIST:", rid, service, user, row_method)

    # View account details
    acc_id = rows[0][0]
    acc = db.get_account_by_id(db_file, acc_id)
    rid, enc_service, enc_user, enc_pass, row_method = acc
    service = crypto.decrypt_password(enc_service, row_method)
    user = crypto.decrypt_password(enc_user, row_method)
    pw = crypto.decrypt_password(enc_pass, row_method)
    print("DETAIL:", rid, service, user, pw, row_method)

    # Delete and verify
    deleted = db.delete_account_by_id(db_file, acc_id)
    print("Deleted:", deleted)
    rows2 = db.list_accounts(db_file)
    print("Rows count after delete:", len(rows2))


if __name__ == "__main__":
    main()


import db
import user_mgmt


def main():
    print("Velkommen til Password Bank!")
    while True:
        print("\n1. Logg inn\n2. Registrer ny bruker\n3. Avslutt")
        choice = input("Velg et alternativ (1-3): ")
        if choice == "1":
            username = input("Brukernavn: ")
            password = input("Masterpassord: ")
            if user_mgmt.authenticate_user(username, password):
                print(f"Innlogging vellykket. Velkommen, {username}!")
                user_session(username)
            else:
                print("Feil brukernavn eller passord.")
        elif choice == "2":
            username = input("Velg brukernavn: ")
            password = input("Velg masterpassord: ")
            if user_mgmt.register_user(username, password):
                print("Bruker registrert. Du kan nå logge inn.")
            else:
                print("Brukernavn er allerede i bruk.")
        elif choice == "3":
            print("Avslutter...")
            break
        else:
            print("Ugyldig valg, prøv igjen.")


def user_session(username):
    db_file = user_mgmt.get_user_db_file(username)
    key_file = user_mgmt.get_user_key_file(username)
    db.init_db(db_file)
    while True:
        print("\n==== Password Bank ====")
        print("1. Legg til konto")
        print("2. Vis alle kontoer")
        print("3. Se detaljer for en konto")
        print("4. Slett en konto")
        print("5. Logg ut")
        choice = input("Velg et alternativ (1-5): ")
        if choice == "1":
            service = input("Tjeneste (f.eks. Gmail): ")
            acc_username = input("Brukernavn: ")
            password = input("Passord: ")
            db.add_account(db_file, key_file, service, acc_username, password)
            print(f"Lagt til {service} ({acc_username})")
        elif choice == "2":
            accounts = db.list_accounts(db_file)
            if not accounts:
                print("Ingen konti funnet.")
            else:
                print("\n--- Lagrede kontoer ---")
                for acc in accounts:
                    print(f"[{acc[0]}] {acc[1]} - {acc[2]}")
        elif choice == "3":
            acc_id = input("Skriv inn ID-en til kontoen du vil se: ")
            try:
                acc_id_int = int(acc_id)
            except ValueError:
                print("Ugyldig ID. Vennligst skriv inn et tall.")
                continue
            account = db.get_account_by_id(db_file, key_file, acc_id_int)
            if account:
                print("\n--- Kontodetaljer ---")
                print(f"ID: {account[0]}")
                print(f"Tjeneste: {account[1]}")
                print(f"Brukernavn: {account[2]}")
                show_pw = input("Vil du vise passordet? (j/n): ").strip().lower()
                if show_pw == "j":
                    print(f"Passord: {account[3]}")
                else:
                    print("Passord: [skjult]")
            else:
                print("Fant ingen konto med den ID-en.")
        elif choice == "4":
            acc_id = input("Skriv inn ID-en til kontoen du vil slette: ")
            try:
                acc_id_int = int(acc_id)
            except ValueError:
                print("Ugyldig ID. Vennligst skriv inn et tall.")
                continue
            account_meta = db.get_account_meta_by_id(db_file, acc_id_int)
            if not account_meta:
                print("Fant ingen konto med den ID-en.")
                continue
            print(f"Du er i ferd med å slette kontoen: {account_meta[1]} ({account_meta[2]})")
            confirm = input("Er du sikker? (j/n): ").strip().lower()
            if confirm == "j":
                if db.delete_account_by_id(db_file, acc_id_int):
                    print("Kontoen ble slettet.")
                else:
                    print("Noe gikk galt. Kontoen ble ikke slettet.")
            else:
                print("Sletting avbrutt.")
        elif choice == "5":
            print("Logger ut...")
            break
        else:
            print("Ugyldig valg, prøv igjen.")


if __name__ == "__main__":
    main()

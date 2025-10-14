from CeasarCipher import decrypt

if __name__ == "__main__":
    cipher_text = input("Enter the encrypted message: ")
    print("\nBruteforcing all possible Caesar cipher shifts (k=0 to 25):\n")
    for k in range(26):
        print(f"Trying shift k={k}:")
        candidate = decrypt(cipher_text, k, verbose=False)
        print(candidate)
        answer = input("Does this look correct? (y/n): ").strip().lower()
        if answer == 'y':
            print(f"\nDecryption found with k={k}: {candidate}")
            break
    else:
        print("\nNo valid decryption found.")


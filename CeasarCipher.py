# Shift cipher (Caesar cipher) for English alphabet (A=0, ..., Z=25)
def letter_to_num(letter):
    """Convert a letter to a number (A=0, B=1, ..., Z=25)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    letter = letter.upper()
    if letter in alphabet:
        return alphabet.index(letter)
    return None

def num_to_letter(num):
    """Convert a number (0-25) to a letter (A-Z)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return alphabet[num % 26]

def text_to_nums(text):
    """Convert text to a list of numbers, non-letters as None."""
    return [letter_to_num(c) for c in text]

def nums_to_text(nums):
    """Convert a list of numbers to text, None as original char."""
    return ''.join(num_to_letter(n) if n is not None else '?' for n in nums)

def encrypt(text, k=3, verbose=True):
    """Encrypt text using Caesar cipher with shift k. Verbose shows steps."""
    nums = text_to_nums(text)
    if verbose:
        print("Original text:", text)
        print("Numeric representation:", [n if n is not None else '-' for n in nums])
    shifted = [(n + k) % 26 if n is not None else None for n in nums]
    if verbose:
        print(f"Shifted by k={k}:", [n if n is not None else '-' for n in shifted])
    result = ''
    for i, char in enumerate(text):
        if nums[i] is not None:
            result += num_to_letter(shifted[i])
        else:
            result += char
    if verbose:
        print("Encrypted text:", result)
    return result

def decrypt(text, k=3, verbose=True):
    """Decrypt text using Caesar cipher with shift k. Verbose shows steps."""
    nums = text_to_nums(text)
    if verbose:
        print("Encrypted text:", text)
        print("Numeric representation:", [n if n is not None else '-' for n in nums])
    shifted = [(n - k) % 26 if n is not None else None for n in nums]
    if verbose:
        print(f"Shifted by -k={-k}:", [n if n is not None else '-' for n in shifted])
    result = ''
    for i, char in enumerate(text):
        if nums[i] is not None:
            result += num_to_letter(shifted[i])
        else:
            result += char
    if verbose:
        print("Decrypted text:", result)
    return result

if __name__ == "__main__":
    mode = input("Type 'e' to encrypt or 'd' to decrypt: ").strip().lower()
    text = input("Enter your message: ")
    k = input("Enter shift (k, default 3): ").strip()
    k = int(k) if k.isdigit() else 3
    if mode == 'e':
        encrypt(text, k, verbose=True)
    elif mode == 'd':
        decrypt(text, k, verbose=True)
    else:
        print("Invalid mode. Use 'e' or 'd'.")

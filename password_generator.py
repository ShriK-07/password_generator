import random
import string
import tkinter as tk
from tkinter import messagebox
import pyperclip
from datetime import datetime

# ------------------ Password Generator Logic ------------------
def generate_password():
    try:
        length = int(length_entry.get())
        if length < 4:
            messagebox.showwarning("Weak Length", "Password length should be at least 4!")
            return
    except ValueError:
        messagebox.showerror("Error", "Please enter a valid number for length.")
        return

    characters = ""
    if upper_var.get():
        characters += string.ascii_uppercase
    if lower_var.get():
        characters += string.ascii_lowercase
    if digits_var.get():
        characters += string.digits
    if symbols_var.get():
        characters += string.punctuation

    if not characters:
        messagebox.showerror("Error", "Please select at least one character type!")
        return

    password = ''.join(random.choice(characters) for _ in range(length))
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    update_strength(password)
    save_password(password)

# ------------------ Password Strength Evaluation ------------------
def evaluate_strength(password):
    length_score = len(password) >= 12
    upper = any(c.isupper() for c in password)
    lower = any(c.islower() for c in password)
    digits = any(c.isdigit() for c in password)
    symbols = any(c in string.punctuation for c in password)

    score = sum([length_score, upper, lower, digits, symbols])
    return score

def update_strength(password):
    score = evaluate_strength(password)
    colors = ["red", "orange", "yellow", "lightgreen", "green"]
    labels = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]

    strength_label.config(text=f"Strength: {labels[score-1] if score else 'Very Weak'}", 
                          fg=colors[score-1] if score else "red")

# ------------------ Clipboard Function ------------------
def copy_password():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Empty", "Generate a password first!")
        return
    pyperclip.copy(password)
    messagebox.showinfo("Copied", "Password copied to clipboard!")

# ------------------ Password History Saver ------------------
def save_password(password):
    with open("password_history.txt", "a") as f:
        f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  {password}\n")

# ------------------ Password Show/Hide Toggle ------------------
def toggle_password():
    if password_entry.cget('show') == '*':
        password_entry.config(show='')
        toggle_btn.config(text="Hide")
    else:
        password_entry.config(show='*')
        toggle_btn.config(text="Show")

# ------------------ GUI Setup ------------------
root = tk.Tk()
root.title("Advanced Password Generator")
root.geometry("420x450")
root.resizable(False, False)
root.config(bg="#f0f4f7")

tk.Label(root, text="Password Generator", font=("Arial", 16, "bold"), bg="#f0f4f7").pack(pady=10)

# Length Entry
frame = tk.Frame(root, bg="#f0f4f7")
frame.pack(pady=5)
tk.Label(frame, text="Password Length:", bg="#f0f4f7").pack(side="left", padx=5)
length_entry = tk.Entry(frame, width=10)
length_entry.insert(0, "12")
length_entry.pack(side="left")

# Checkboxes
upper_var = tk.BooleanVar(value=True)
lower_var = tk.BooleanVar(value=True)
digits_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=False)

tk.Checkbutton(root, text="Include Uppercase", variable=upper_var, bg="#f0f4f7").pack(anchor='w', padx=40)
tk.Checkbutton(root, text="Include Lowercase", variable=lower_var, bg="#f0f4f7").pack(anchor='w', padx=40)
tk.Checkbutton(root, text="Include Digits", variable=digits_var, bg="#f0f4f7").pack(anchor='w', padx=40)
tk.Checkbutton(root, text="Include Symbols", variable=symbols_var, bg="#f0f4f7").pack(anchor='w', padx=40)

# Buttons and Output
tk.Button(root, text="Generate Password", command=generate_password, bg="#0078d7", fg="white", width=20).pack(pady=10)

password_entry = tk.Entry(root, width=35, font=("Consolas", 12), justify='center', show='*')
password_entry.pack(pady=5)

toggle_btn = tk.Button(root, text="Show", command=toggle_password, width=8)
toggle_btn.pack(pady=5)

tk.Button(root, text="Copy to Clipboard", command=copy_password, bg="#28a745", fg="white", width=20).pack(pady=10)

# Strength Label
strength_label = tk.Label(root, text="Strength: -", bg="#f0f4f7", font=("Arial", 11, "bold"))
strength_label.pack(pady=10)

# Footer
tk.Label(root, text="All passwords saved to password_history.txt", fg="gray", bg="#f0f4f7").pack(side="bottom", pady=10)

root.mainloop()

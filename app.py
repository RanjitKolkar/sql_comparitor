import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import hashlib
import difflib
import os

def compute_hash(file_path, algo="sha256"):
    """Compute hash for the given file."""
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def browse_file(entry_widget):
    """Open file dialog and insert the chosen path into entry."""
    path = filedialog.askopenfilename(filetypes=[("SQL files", "*.sql"), ("All files", "*.*")])
    if path:
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, path)

def compare_files():
    file1 = entry1.get().strip()
    file2 = entry2.get().strip()
    if not file1 or not file2:
        messagebox.showwarning("Missing File", "Please select both SQL files.")
        return

    if not os.path.exists(file1) or not os.path.exists(file2):
        messagebox.showerror("File Error", "One or both selected files do not exist.")
        return

    # Compute hashes
    hash1_md5 = compute_hash(file1, "md5")
    hash2_md5 = compute_hash(file2, "md5")
    hash1_sha = compute_hash(file1, "sha256")
    hash2_sha = compute_hash(file2, "sha256")

    # Compare hashes
    result_text = f"File 1: {os.path.basename(file1)}\nMD5: {hash1_md5}\nSHA256: {hash1_sha}\n\n"
    result_text += f"File 2: {os.path.basename(file2)}\nMD5: {hash2_md5}\nSHA256: {hash2_sha}\n\n"

    if hash1_sha == hash2_sha:
        result_text += "✅ Files are identical (no tampering detected)"
    else:
        result_text += "⚠️ Files differ! Possible tampering detected."

    result_box.config(state="normal")
    result_box.delete(1.0, tk.END)
    result_box.insert(tk.END, result_text)
    result_box.config(state="disabled")

    # Show differences
    with open(file1, "r", encoding="utf-8") as f1, open(file2, "r", encoding="utf-8") as f2:
        text1 = f1.readlines()
        text2 = f2.readlines()

    diff = difflib.unified_diff(text1, text2, fromfile=file1, tofile=file2, lineterm="")
    diff_text = "".join(diff)
    diff_box.config(state="normal")
    diff_box.delete(1.0, tk.END)
    diff_box.insert(tk.END, diff_text if diff_text else "No differences found.")
    diff_box.config(state="disabled")


# ----------------- UI -----------------
root = tk.Tk()
root.title("SQL File Hash & Difference Checker")
root.geometry("900x700")
root.configure(bg="#f7f9fc")

tk.Label(root, text="SQL File Hash Comparator", font=("Helvetica", 16, "bold"), bg="#f7f9fc").pack(pady=10)

frame = tk.Frame(root, bg="#f7f9fc")
frame.pack(pady=10)

entry1 = tk.Entry(frame, width=70)
entry1.grid(row=0, column=1, padx=10, pady=5)
tk.Button(frame, text="Browse File 1", command=lambda: browse_file(entry1)).grid(row=0, column=2, padx=5)

entry2 = tk.Entry(frame, width=70)
entry2.grid(row=1, column=1, padx=10, pady=5)
tk.Button(frame, text="Browse File 2", command=lambda: browse_file(entry2)).grid(row=1, column=2, padx=5)

tk.Button(root, text="Compare Files", command=compare_files, bg="#4caf50", fg="white", width=20).pack(pady=10)

# Results section
tk.Label(root, text="Hash Comparison Results:", bg="#f7f9fc", font=("Arial", 12, "bold")).pack()
result_box = scrolledtext.ScrolledText(root, height=8, width=100, state="disabled", bg="#fff")
result_box.pack(padx=10, pady=10)

tk.Label(root, text="File Differences:", bg="#f7f9fc", font=("Arial", 12, "bold")).pack()
diff_box = scrolledtext.ScrolledText(root, height=20, width=100, state="disabled", bg="#fff")
diff_box.pack(padx=10, pady=10)

root.mainloop()

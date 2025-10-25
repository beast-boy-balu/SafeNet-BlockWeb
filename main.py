import sys
import os
import platform
import ctypes
import tkinter as tk
from tkinter import messagebox, filedialog
import requests
import webbrowser
import secrets
import string
from PIL import Image, ImageTk
import tkinter.ttk as ttk

# --- Auto-Run As Admin (Windows only) ---
def run_as_admin():
    if platform.system() == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                script = os.path.abspath(sys.argv[0])
                params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", sys.executable, f'"{script}" {params}', None, 1)
                sys.exit()
        except Exception as e:
            print("Admin elevation error:", str(e))
            sys.exit()
run_as_admin()

# --- Constants ---
VT_API_KEY = "b08753e41ef61863bd3a2e667cc093b41ca12b3b6232be34dfa352a39a9fec55"
URLSCAN_API_KEY = "0198706f-e9e9-7094-8b62-17e9b4414600"

# --- Password Generator ---
def generate_password(length=8):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))
PASSWORD = generate_password()

def resource_path(relative_path):
    """ Get absolute path to resource (dev and PyInstaller compatible) """
    try:
        base_path = sys._MEIPASS  # PyInstaller temp folder
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

html_path = resource_path("about.html")
with open(html_path, "r", encoding="utf-8") as f:
    about_content = f.read()
# You can now display it in a Tkinter widget or open it in browser

# --- GUI Setup ---
root = tk.Tk()
root.title("SafeNet - Website Blocker & Checker")
root.state('zoomed')
root.configure(bg="#0d0d0d")  # Neon dark background

# --- Scrollable Canvas ---
main_canvas = tk.Canvas(root, bg="#0d0d0d", highlightthickness=0)
scrollbar = tk.Scrollbar(root, orient="vertical", command=main_canvas.yview)
scrollable_frame = tk.Frame(main_canvas, bg="#0d0d0d")

scrollable_frame.bind(
    "<Configure>",
    lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
)

main_canvas.create_window((0, 0), window=scrollable_frame, anchor="n")
main_canvas.configure(yscrollcommand=scrollbar.set)

main_canvas.pack(side="left", fill="both", expand=True)
scrollbar.pack(side="right", fill="y")

# Force the inner frame to always match canvas width
def resize_inner_frame(event):
    canvas_width = event.width
    main_canvas.itemconfig(inner_window, width=canvas_width)

inner_window = main_canvas.create_window((0, 0), window=scrollable_frame, anchor="n")
main_canvas.bind("<Configure>", resize_inner_frame)


def _on_mousewheel(event):
    main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

main_canvas.bind_all("<MouseWheel>", _on_mousewheel)

# --- Utility Functions ---
def open_html():
    try:
        webbrowser.open(html_path)
    except:
        messagebox.showerror("Error", "Unable to open help file")

def get_hosts_path():
    return r"C:\Windows\System32\drivers\etc\hosts" if platform.system() == "Windows" else "/etc/hosts"

def notify_password(copy=True):
    if copy:
        root.clipboard_clear()
        root.clipboard_append(PASSWORD)
    messagebox.showinfo("🔑 Admin Password", f"Today's password: {PASSWORD}\n\n(Copied to clipboard!)")

def is_full_url(text):
    return text.startswith("http://") or text.startswith("https://") or '/' in text

def load_domains_into(entry_widget):
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if file_path:
        try:
            with open(file_path, "r") as file:
                domains = file.read().strip().splitlines()
                entry_widget.insert(tk.END, "\n".join(domains))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file:\n{e}")

# --- Button Style ---
def neon_button(master, text, command, bg="#0d0d0d", fg="#39ff14", hover="#00ff99"):
    return tk.Button(master, text=text, command=command, font=("Courier New", 10, "bold"),
                     bg=bg, fg=fg, activebackground=hover, activeforeground="black",
                     relief="solid", bd=1, padx=10, pady=4)

# --- Clear Fields ---
def clear_check_fields():
    url_entry.delete("1.0", tk.END)

def clear_block_fields():
    block_entry.delete("1.0", tk.END)
    block_pwd.delete(0, tk.END)

def clear_unblock_fields():
    unblock_entry.delete("1.0", tk.END)
    unblock_pwd.delete(0, tk.END)

# --- Core Functionalities ---
import time

import tkinter.ttk as ttk

def check_site():
    urls = url_entry.get("1.0", tk.END).strip().splitlines()
    urls = [u.strip().lower() for u in urls if u.strip()]
    total = len(urls)

    # --- Create waiting popup ---
    wait_win = tk.Toplevel()
    wait_win.title("Scanning...")

    # Center the popup
    popup_width, popup_height = 350, 150
    screen_width = wait_win.winfo_screenwidth()
    screen_height = wait_win.winfo_screenheight()
    x = (screen_width // 2) - (popup_width // 2)
    y = (screen_height // 2) - (popup_height // 2)
    wait_win.geometry(f"{popup_width}x{popup_height}+{x}+{y}")

    wait_win.transient(root)
    wait_win.grab_set()

    status_label = tk.Label(wait_win, text="Preparing scan...", font=("Arial", 11))
    status_label.pack(pady=10)

    progress = ttk.Progressbar(wait_win, length=250, mode='determinate', maximum=total)
    progress.pack(pady=10)
    wait_win.update()

    all_results = []

    for i, url in enumerate(urls, 1):
        if not url or is_full_url(url):
            all_results.append(f"❌ Skipped invalid: {url}")
            progress['value'] = i
            wait_win.update()
            continue

        # Update status
        status_label.config(text=f"🔍 Scanning: {url} ({i}/{total})")
        progress['value'] = i - 1
        wait_win.update()

        results = []

        # --- VirusTotal ---
        try:
            vt_resp = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params={
                'apikey': VT_API_KEY, 'resource': url
            }).json()
            if vt_resp.get('positives', 0) > 0:
                results.append("🔴 VirusTotal: MALICIOUS")
            else:
                results.append("🟢 VirusTotal: Clean")
        except Exception as e:
            results.append(f"⚠️ VT error: {e}")

        # --- URLScan.io ---
        try:
            headers = {"API-Key": URLSCAN_API_KEY, "Content-Type": "application/json"}
            data = {"url": f"http://{url}", "public": "off"}
            submit = requests.post("https://urlscan.io/api/v1/scan/", headers=headers, json=data)
            scan_uuid = submit.json().get("uuid")
            time.sleep(7)

            result = requests.get(f"https://urlscan.io/api/v1/result/{scan_uuid}/").json()
            verdict = result.get("verdicts", {}).get("overall", {}).get("score", 0)
            if verdict > 0:
                results.append(f"🔴 URLScan: Score {verdict} (Suspicious)")
            else:
                results.append("🟢 URLScan: No threats found")
        except Exception as e:
            results.append(f"⚠️ URLScan error: {e}")

        all_results.append(f"🌐 {url}\n" + "\n".join(results))
        progress['value'] = i
        wait_win.update()

    wait_win.destroy()
    messagebox.showinfo("All Scan Results", "\n\n".join(all_results))


def block_site():
    sites = block_entry.get("1.0", tk.END).strip().splitlines()
    pwd = block_pwd.get()
    if not sites or not pwd:
        messagebox.showerror("Error", "Please enter a website and password")
        return
    if pwd != PASSWORD:
        messagebox.showerror("Error", "Incorrect password")
        return

    hosts_path = get_hosts_path()
    try:
        with open(hosts_path, "r+") as f:
            lines = f.readlines()
            f.seek(0)
            existing = [line.strip() for line in lines]
            for line in existing:
                f.write(line + "\n")
            for site in sites:
                site = site.strip().lower()
                if not site or is_full_url(site): continue
                if all(site not in line for line in existing):
                    f.write(f"127.0.0.1 {site}\n")
                    if not site.startswith("www."):
                        f.write(f"127.0.0.1 www.{site}\n")
        os.system("ipconfig /flushdns")
        messagebox.showinfo("Blocked", "All valid domains blocked.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def unblock_site():
    sites = unblock_entry.get("1.0", tk.END).strip().splitlines()
    pwd = unblock_pwd.get()
    if not sites or not pwd:
        messagebox.showerror("Missing", "Fill in all fields")
        return
    if pwd != PASSWORD:
        messagebox.showerror("Wrong Password", "Incorrect password")
        return
    try:
        with open(get_hosts_path(), "r") as f:
            lines = f.readlines()
        with open(get_hosts_path(), "w") as f:
            for line in lines:
                if all(site.strip().lower() not in line for site in sites):
                    f.write(line)
        os.system("ipconfig /flushdns")
        messagebox.showinfo("Unblocked", "All domains unblocked successfully.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- Header ---
header_frame = tk.Frame(scrollable_frame, bg="#0d0d0d")
header_frame.pack(fill="x", pady=(10, 20))
header_frame.columnconfigure(0, weight=1)
header_frame.columnconfigure(1, weight=1)
header_frame.columnconfigure(2, weight=1)

heading_label = tk.Label(
    header_frame,
    text="🛡️ Malicious Website Blocker",
    font=("Courier New", 22, "bold"),
    bg="#0d0d0d", fg="#39ff14"
)
heading_label.grid(row=0, column=1, sticky="n", padx=10)
heading_label.bind("<Button-1>", lambda e: notify_password())

try:
    logo_path = resource_path("logo.png")

    # Load and resize before converting to PhotoImage
    logo_image = Image.open(logo_path)
    logo_image = logo_image.resize((50, 50), Image.Resampling.LANCZOS)
    logo_photo = ImageTk.PhotoImage(logo_image)

    # Create label and place it in header_frame
    logo_label = tk.Label(header_frame, image=logo_photo, bg="#0d0d0d")
    logo_label.image = logo_photo  # Keep a reference to prevent garbage collection
    logo_label.grid(row=0, column=2, sticky="ne", padx=10)

except:
    pass
# --- Horizontal Container for Sections ---
section_container = tk.Frame(scrollable_frame, bg="#0d0d0d")
# Configure 4 equal columns for grid layout
for i in range(4):
    section_container.columnconfigure(i, weight=1)

section_container.pack(fill="x", expand=True, pady=20)



# --- Check Section ---
frame1 = tk.Frame(section_container, bg="#0d0d0d", bd=2, relief="solid",
                  highlightbackground="#39ff14", highlightthickness=2)
frame1.grid(row=0, column=0, padx=20, pady=10, sticky="nsew")

tk.Label(frame1, text="🔍 Check Website", font=("Courier New", 16, "bold"), bg="#0d0d0d", fg="#39ff14").pack(pady=(10, 5))
tk.Label(frame1, text="Enter Domain Name:", bg="#0d0d0d", fg="#39ff14").pack()

url_entry = tk.Text(frame1, width=30, height=5, bg="#1a1a1a", fg="#39ff14", insertbackground="#39ff14", font=("Courier New", 10))
url_entry.pack(pady=5)

neon_button(frame1, "📂 Load File", lambda: load_domains_into(url_entry)).pack(pady=5)
neon_button(frame1, "Check", lambda: [check_site(), clear_check_fields()], bg="#003300").pack(pady=(0, 10))

# --- Block Section ---
frame2 = tk.Frame(section_container, bg="#0d0d0d", bd=2, relief="solid",
                  highlightbackground="#39ff14", highlightthickness=2)
frame2.grid(row=0, column=1, padx=20, pady=10, sticky="nsew")

tk.Label(frame2, text="⛔ Block Website", font=("Courier New", 16, "bold"), bg="#0d0d0d", fg="#39ff14").pack(pady=(10, 5))
tk.Label(frame2, text="Domain to Block:", bg="#0d0d0d", fg="#39ff14").pack()

block_entry = tk.Text(frame2, width=30, height=5, bg="#1a1a1a", fg="#39ff14", insertbackground="#39ff14", font=("Courier New", 10))
block_entry.pack(pady=5)

neon_button(frame2, "📂 Load File", lambda: load_domains_into(block_entry)).pack(pady=5)
tk.Label(frame2, text="Password:", bg="#0d0d0d", fg="#39ff14").pack()
block_pwd = tk.Entry(frame2, show="*", width=30, bg="#1a1a1a", fg="#39ff14", insertbackground="#39ff14", font=("Courier New", 10))
block_pwd.pack(pady=5)
neon_button(frame2, "Block", lambda: [block_site(), clear_block_fields()], bg="#330000").pack(pady=(0, 10))

# --- Unblock Section ---
frame3 = tk.Frame(section_container, bg="#0d0d0d", bd=2, relief="solid",
                  highlightbackground="#39ff14", highlightthickness=2)
frame3.grid(row=0, column=2, padx=20, pady=10, sticky="nsew")

tk.Label(frame3, text="✅ Unblock Website", font=("Courier New", 16, "bold"), bg="#0d0d0d", fg="#39ff14").pack(pady=(10, 5))
tk.Label(frame3, text="Domain to Unblock:", bg="#0d0d0d", fg="#39ff14").pack()

unblock_entry = tk.Text(frame3, width=30, height=5, bg="#1a1a1a", fg="#39ff14", insertbackground="#39ff14", font=("Courier New", 10))
unblock_entry.pack(pady=5)

neon_button(frame3, "📂 Load File", lambda: load_domains_into(unblock_entry)).pack(pady=5)
tk.Label(frame3, text="Password:", bg="#0d0d0d", fg="#39ff14").pack()
unblock_pwd = tk.Entry(frame3, show="*", width=30, bg="#1a1a1a", fg="#39ff14", insertbackground="#39ff14", font=("Courier New", 10))
unblock_pwd.pack(pady=5)
neon_button(frame3, "Unblock", lambda: [unblock_site(), clear_unblock_fields()], bg="#003333").pack(pady=(0, 10))

frame4 = tk.Frame(section_container, bg="#0d0d0d", bd=2, relief="solid",
                  highlightbackground="#39ff14", highlightthickness=2)
frame4.grid(row=1, column=1, padx=20, pady=10, sticky="nsew")

# --- Heading ---
tk.Label(frame4, text="🧠 Smart Suggestions", font=("Courier New", 16, "bold"),
         bg="#0d0d0d", fg="#39ff14").pack(pady=(10, 5))

# --- Scrollable Suggestions Box ---
suggest_frame = tk.Frame(frame4, bg="#0d0d0d")
suggest_frame.pack(fill="both", expand=True, padx=5, pady=5)

suggest_scrollbar = tk.Scrollbar(suggest_frame, orient="vertical")
suggest_scrollbar.pack(side="right", fill="y")

suggest_box = tk.Text(suggest_frame, width=40, height=22, bg="#1a1a1a", fg="#39ff14",
                      insertbackground="#39ff14", font=("Courier New", 10), wrap="word",
                      yscrollcommand=suggest_scrollbar.set)
suggest_scrollbar.config(command=suggest_box.yview)

suggest_text = """\
📌 Basic Usage:
• Enter only domain names (e.g., example.com)
• Use 'Load File' to scan lists of domains
• Click the header to reveal today’s password

🛡️ Blocking Tips:
• Don’t block essential services (e.g., google.com)
• Block patterns like *.ads, *.tracking
• Flush DNS after every block or unblock

🧠 Multi-Engine Checks:
• Uses VirusTotal & URL Scanner to verify threats
• More engines = fewer false negatives
• Ideal for phishing and scam detection

🧠 Pro Suggestions:
• Use the Check tab before blocking anything
• Create backups of the hosts file before changes
• Future update: AI-powered auto-block rules

🧰 Utilities:
• ESC exits fullscreen
• 'About' opens help page
• Add more tools in frame4 later (like log viewer!)
"""
suggest_box.insert("1.0", suggest_text)
suggest_box.config(state="disabled")
suggest_box.pack(fill="both", expand=True)


# --- Footer ---
footer = tk.Frame(scrollable_frame, bg="#0d0d0d")
footer.pack(pady=10)
neon_button(footer, "About", open_html).pack(side="left", padx=10)
neon_button(footer, "❌ Exit", root.destroy, bg="#330000", fg="#ff4d4d").pack(side="right", padx=10)

# --- Auto Show Password ---
def delayed_password():
    notify_password()
    url_entry.focus_set()

root.after(300, delayed_password)
root.mainloop()
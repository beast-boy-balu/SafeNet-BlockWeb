# SafeNet BlockWeb v2  
**Advanced Malicious Website Blocker for Windows**

> “Block the danger before it reaches your browser.”

---

## Overview
**SafeNet BlockWeb v2** is a **Python-based desktop application** that detects, blocks, and unblocks potentially dangerous websites using both **local system control** and **real-time threat intelligence APIs**.

It integrates **VirusTotal** and **URLScan.io** for domain reputation analysis, leveraging cloud-based scanning and sandbox results.  
Blocked domains are redirected to `127.0.0.1` via the system’s `hosts` file — cutting off access at the OS level.

---

## Key Features
**Real-time threat analysis** using VirusTotal & URLScan APIs  
**Local blocking & unblocking** via hosts file modification  
**DNS cache auto-flush** after every block/unblock  
**Password-protected session security**  
**Bulk domain upload** for batch scanning  
**Interactive GUI (Tkinter-based)**  
**Offline execution supported** after API checks  
**Packaged EXE** using `PyInstaller`  

---

## Tech Stack
- **Languages:** Python, HTML, CSS, JavaScript  
- **APIs:** VirusTotal API, URLScan.io API  
- **Libraries:** Requests, Tkinter, OS, Subprocess  
- **Packaging:** PyInstaller (`.exe` build)  
- **Platform:** Windows 10 / 11  

---

## Project Structure
BlockWeb/
├── build/
├── dist/
│ └── BlockWeb.exe # Executable build
├── about.html # Project About Page
├── icon.ico
├── logo.png
├── main.py # Core Application
├── main.spec # PyInstaller build spec
├── .venv/
└── README.md # (You’re reading this)

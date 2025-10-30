# 🛡️ SafeNet BlockWeb v2  
**Advanced Malicious Website Blocker for Windows**  
**高度な悪意のあるウェブサイトブロッカー（Windows向け）**

> “Block the danger before it reaches your browser.”  
> 「危険がブラウザに届く前に、ブロックせよ。」

---

## Overview  
**SafeNet BlockWeb v2** is a **Python-based desktop application** that detects, blocks, and unblocks potentially dangerous websites using both **local system control** and **real-time threat intelligence APIs**.  

It integrates **VirusTotal** and **URLScan.io** for domain reputation analysis, leveraging cloud-based scanning and sandbox results.  
Blocked domains are redirected to `127.0.0.1` via the system’s `hosts` file — cutting off access at the OS level.  

---

## 概要  
**SafeNet BlockWeb v2** は、**Pythonベースのデスクトップアプリケーション**であり、**ローカルシステム制御**と**リアルタイム脅威インテリジェンスAPI**を組み合わせて、潜在的に危険なウェブサイトを検出・ブロック・解除します。  

**VirusTotal** と **URLScan.io** を統合し、クラウドベースのスキャンおよびサンドボックス結果を活用してドメインの評判分析を実施します。  
ブロック対象のドメインは `hosts` ファイルを介して `127.0.0.1` にリダイレクトされ、OSレベルでアクセスを遮断します。  

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

## 主な機能  
**VirusTotal & URLScan API** によるリアルタイム脅威分析  
**hostsファイルの自動編集**によるローカルブロック/解除機能  
**ブロック/解除ごとにDNSキャッシュを自動クリア**  
**パスワード保護付きセッションセキュリティ**  
**複数ドメインの一括スキャン（バルクアップロード対応）**  
**TkinterベースのインタラクティブGUI**  
**APIチェック後のオフライン実行をサポート**  
**PyInstallerによるEXEパッケージ化**

---

## Tech Stack  
- **Languages:** Python, HTML, CSS, JavaScript  
- **APIs:** VirusTotal API, URLScan.io API  
- **Libraries:** Requests, Tkinter, OS, Subprocess  
- **Packaging:** PyInstaller (`.exe` build)  
- **Platform:** Windows 10 / 11  

---

## 技術スタック  
- **言語:** Python, HTML, CSS, JavaScript  
- **API:** VirusTotal API, URLScan.io API  
- **ライブラリ:** Requests, Tkinter, OS, Subprocess  
- **パッケージング:** PyInstaller（`.exe` ビルド）  
- **対応プラットフォーム:** Windows 10 / 11  

---

## Project Structure  
BlockWeb/  
├── build/  
├── dist/  
│   └── BlockWeb.exe # Executable build  
├── about.html # Project About Page  
├── icon.ico  
├── logo.png  
├── main.py # Core Application  
├── main.spec # PyInstaller build spec  
├── .venv/  
└── README.md # (You’re reading this)  

---

## プロジェクト構成  
BlockWeb/  
├── build/  
├── dist/  
│   └── BlockWeb.exe # 実行ファイル  
├── about.html # プロジェクト概要ページ  
├── icon.ico  
├── logo.png  
├── main.py # メインアプリケーション  
├── main.spec # PyInstaller ビルド設定  
├── .venv/  
└── README.md # （このファイル）  

---

## Developer’s Message  
This project was designed to **protect users from cyber threats** through proactive local control.  
SafeNet BlockWeb v2 is not just a blocker — it represents a **modern edge-level defense framework** built with simplicity and safety in mind.  

---

## 開発者メッセージ  
本プロジェクトは、**サイバー脅威からユーザーを守る**ことを目的に設計されました。  
**SafeNet BlockWeb v2** は単なるブロッカーではなく、「安全性」と「簡潔さ」を両立させた **新しいエッジレベルセキュリティ基盤** を目指しています。  

########################################################################
#   _____ _      _____ _____  _      _    _  _____ 
#  / ____| |    / ____|  __ \| |    | |  | |/ ____|
# | (___ | |   | |  __| |__) | |    | |  | | (___  
#  \___ \| |   | | |_ |  ___/| |    | |  | |\___ \ 
#  ____) | |___| |__| | |    | |____| |__| |____) |
# |_____/|______\_____|_|    |______|\____/|_____/ 
#                                          
# FILE        : app.py
# AUTHOR      : @frenchpythonlover
# COPYRIGHT   : (c) 2026 SLGPlus
# CONTEXT     : backend_api_core
########################################################################

import json
import os
import time
import uuid
import random
import datetime
import yaml
import mariadb
import requests
import openpyxl
import logging
import hashlib
import re
import pytz

from flask import Flask, request, Response
from flask_restful import Resource, Api
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from waitress import serve

############################################################
# CONFIG
############################################################

with open("config.yml", "r", encoding="utf-8") as f:
    CONFIG = yaml.safe_load(f)

DB_CONFIG = CONFIG["database"]

SESSION_TTL = CONFIG["security"]["session_ttl"]
TESTERSPIN = CONFIG["security"]["testers_pin"]
FLARUM_MASTER_API_KEY = CONFIG["apikeys"]["flarum_master"]
GEMINI_API_KEYS = CONFIG["apikeys"]["gemini_keys"] 
_gemini_key_index = 0
alphabet = 'abcdefghijklmnopqrstuvwxyz'
alphabetmaj = alphabet.upper()

logging.basicConfig(level=logging.INFO)

############################################################
# APP
############################################################

app = Flask(__name__)
api = Api(app)

CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True
)

############################################################
# DB POOL
############################################################

POOL = mariadb.ConnectionPool(
    pool_name="slgpool",
    pool_size=DB_CONFIG["pool_size"],
    host=DB_CONFIG["host"],
    port=DB_CONFIG["port"],
    user=DB_CONFIG["user"],
    password=DB_CONFIG["password"],
    database=DB_CONFIG["database"]
)

def db():
    return POOL.get_connection()

############################################################
# ANALYTICS
############################################################

class AnalyticsPath:
    spreadsheet = "/serverfiles/api/db/stats.xlsx"

def update_hits():
    wb = openpyxl.open(AnalyticsPath.spreadsheet)
    ws = wb.active
    cdate = datetime.date.today().strftime("%d/%m/%Y")
    ws.append([cdate])
    wb.save(AnalyticsPath.spreadsheet)
    return True

############################################################
# HELPERS
############################################################

def _client_ip():
    return request.json["IP"]

def _generate_id():
    tid = []

    for i in range(6):
        r = random.randint(0,2)

        if r == 0:
            tid.append(alphabet[random.randint(0,25)])

        elif r == 1:
            tid.append(alphabetmaj[random.randint(0,25)])

        else:
            tid.append(str(random.randint(0,9)))

    return "".join(tid)

def _generate_article_id():
    conn = db()
    cur = conn.cursor()

    while True:
        gid = _generate_id()

        cur.execute(
            "SELECT id FROM news_articles WHERE article_uid=?",
            (gid,)
        )

        if cur.fetchone() is None:
            conn.close()
            return gid

def _derive_flarum_password(email, prenom, sexe, classe):
    raw = f"{email.lower()}|{prenom.lower()}|{sexe.lower()}|{classe.lower()}|SLGPlus_salt_2026"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def _get_next_gemini_key():
    global _gemini_key_index
    key = GEMINI_API_KEYS[_gemini_key_index % len(GEMINI_API_KEYS)]
    _gemini_key_index += 1
    return key

def _get_time_string():
    tz = pytz.timezone('Europe/Paris')
    return datetime.datetime.now(tz).strftime("%d/%m/%Y %H:%M:%S")


@app.before_request
def log_request():
    args = request.get_json(silent=True) or {}
    print(f"[ REQUEST ] {_get_time_string()} --> {request.method} {request.path} {args.get('IP','?')}")
    
############################################################
# SESSIONS
############################################################

def _session_valid(token):
    conn = db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        "SELECT * FROM sessions WHERE token=?",
        (token,)
    )

    session = cur.fetchone()

    if session is None:
        conn.close()
        return None

    now = int(time.time())

    if now - session["last_active"] > SESSION_TTL:
        cur.execute(
            "DELETE FROM sessions WHERE token=?",
            (token,)
        )
        conn.commit()
        conn.close()
        return None

    cur.execute(
        "UPDATE sessions SET last_active=? WHERE token=?",
        (now, token)
    )

    conn.commit()

    cur.execute(
        """
        SELECT users_accounts.username, users_accounts.role
        FROM users_accounts
        WHERE id=?
        """,
        (session["user_id"],)
    )

    user = cur.fetchone()

    conn.close()

    return {
        "user": user["role"],
        "username": user["username"]
    }

def _create_session(user_role):
    conn = db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        "SELECT * FROM users_accounts WHERE role=? LIMIT 1",
        (user_role,)
    )

    user = cur.fetchone()

    if user is None:
        conn.close()
        return None

    token = uuid.uuid4().hex
    now = int(time.time())
    ip = _client_ip()

    cur.execute(
        """
        INSERT INTO sessions
        (token, user_id, ip_address, created_at, last_active)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            token,
            user["id"],
            ip,
            now,
            now
        )
    )

    cur.execute(
        """
        INSERT INTO connected_users
        (session_token, user_id, ip_address, connected_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            token,
            user["id"],
            ip,
            now
        )
    )

    conn.commit()
    conn.close()

    return token

def _destroy_session(token):
    conn = db()
    cur = conn.cursor()

    now = int(time.time())

    cur.execute(
        """
        UPDATE connected_users
        SET disconnected_at=?
        WHERE session_token=?
        """,
        (now, token)
    )

    cur.execute(
        "DELETE FROM sessions WHERE token=?",
        (token,)
    )

    conn.commit()
    conn.close()

############################################################
# ROUTES
############################################################

class Ping(Resource):
    def get(self):
        maintenance_mode = CONFIG["server"]["maintenance"]["maintenance_mode"]
        if maintenance_mode:
            maintenance_reason = CONFIG["server"]["maintenance"]["reason"]
            status_info = {
                "maintenance":True,
                "reason":maintenance_reason
            }
        else:
            status_info = {
                "maintenance":False
            }
            
        return {'message':'pong','version':CONFIG["server"]["version"],'status':status_info}

############################################################
# LOGIN
############################################################

class Login(Resource):
    def post(self):
        args = request.get_json() or {}

        pin = args.get("pin","")
        user = args.get("user","profs")
        token = args.get("token")

        conn = db()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            "SELECT * FROM users_accounts WHERE role=? LIMIT 1",
            (user,)
        )

        account = cur.fetchone()

        conn.close()

        if account is None:
            return {"message":"wrong_pin"}, 401

        if check_password_hash(account["pin_hash"], pin):

            if token is not None:
                return {"message":"tokenerror"}, 401

            token = _create_session(user)

            return {
                "message":"success",
                "token":token
            }

        return {"message":"wrong_pin"}, 401

############################################################
# CHECK ELEVES
############################################################

class CheckEleves(Resource):
    def post(self):
        pin = request.get_json().get("pin")

        if int(pin) == TESTERSPIN:
            return {
                "message":"redirect",
                "url":"/trfdyhbyxwzexvbhjbvcdrswqsrttyuiohvgfder.html"
            }

        conn = db()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            "SELECT pin_hash FROM users_accounts WHERE role='eleves' LIMIT 1"
        )

        row = cur.fetchone()

        conn.close()

        if row and check_password_hash(row["pin_hash"], pin):
            token = _create_session("eleves")
            return {"message":"success","token":token}

        return {"message":"wrong_pin"}, 401

############################################################
# LOGOUT
############################################################

class Logout(Resource):
    def post(self):
        args = request.get_json() or {}

        token = args.get("token","")

        if not token:
            return {"message":"no_token"}, 400

        _destroy_session(token)

        return {"message":"disconnected"}

############################################################
# CHECK TOKEN
############################################################

class CheckToken(Resource):
    def post(self):
        token = request.json.get("token")

        if token is not None:
            s = _session_valid(token)

            if s is not None:
                return {
                    "message":"connected",
                    "user":s["user"]
                }, 200

        return {"message":"error"}, 401

############################################################
# NEWS
############################################################

class News(Resource):

    def get(self):
        conn = db()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT *
            FROM news_articles
            WHERE approved=1
            ORDER BY id DESC
            """
        )

        rows = cur.fetchall()

        conn.close()

        news = {}

        for i, article in enumerate(rows, start=1):
            news[str(i)] = {
                "id": article["article_uid"],
                "by": article["author"],
                "title": article["title"],
                "content": article["content"],
                "image": article["image_url"]
            }

        return {"message":news}

    def post(self):
        args = request.json or {}

        token = args.get("token","")
        session = _session_valid(token)

        if not session:
            return {"message":"unauthorized"}, 401

        conn = db()
        cur = conn.cursor(dictionary=True)

        if args.get("mode") == "DEL":

            if session["user"] != "admin":
                conn.close()
                return {"message":"unauthorized"},401

            article_id = args.get("id")

            cur.execute(
                "DELETE FROM news_articles WHERE article_uid=?",
                (article_id,)
            )

            conn.commit()
            conn.close()

            return {"message":"succes"}

        article_uid = _generate_article_id()
        cur.execute(
            """
            INSERT INTO news_articles
            (
                article_uid,
                author,
                title,
                content,
                image_url,
                approved,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                article_uid,
                args.get("by","Auteur inconnu"),
                args.get("title",""),
                args.get("content",""),
                args.get("image",""),
                1 if session["user"] == "admin" else 0,
                int(time.time())
            )
        )

        conn.commit()
        conn.close()

        return {
            "message":"success",
            "id":article_uid
        }

############################################################
# CHECK ARTICLE
############################################################

class CheckArticle(Resource):
    def post(self):
        args = request.json or {}

        article_id = args.get("id","")

        conn = db()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT approved
            FROM news_articles
            WHERE article_uid=?
            LIMIT 1
            """,
            (article_id,)
        )

        row = cur.fetchone()

        conn.close()

        if row is None:
            return {
                "message":"error",
                "status":"notfound"
            }

        return {
            "message":"success",
            "status":"approved" if row["approved"] else "unapproved"
        }

############################################################
# LOST AND FOUND
############################################################
class LostAndFound(Resource):
    def get(self):

        conn = db()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT *
            FROM lost_and_found
            ORDER BY id DESC
            """
        )

        rows = cur.fetchall()

        conn.close()

        result = {}

        for row in rows:

            result[str(row["id"])] = {
                "type": row["type"],
                "size": row["size"],
                "brand": row["brand"],
                "image": row["image"],
                "description": row["description"]
            }

        return result, 200
    def post(self):

        args = request.json

        mode = args.get("mode", "post")
        content = args.get("content", {})

        torem = args.get("torem")
        token = args.get("token")

        session = _session_valid(token)

        if session is None:
            return {"message": "unauthorized"}, 401

        if session["user"] != "bvs":
            return {"message": "unauthorized"}, 401

        conn = db()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            "SELECT id FROM users_accounts WHERE role='bvs' LIMIT 1"
        )

        bvs = cur.fetchone()

        if mode == "post":

            cur.execute(
                """
                INSERT INTO lost_and_found
                (
                    type,
                    size,
                    brand,
                    image,
                    description,
                    created_by,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    content.get("type",""),
                    content.get("size",""),
                    content.get("brand",""),
                    content.get("image",""),
                    content.get("description",""),
                    bvs["id"],
                    int(time.time())
                )
            )

            conn.commit()
            conn.close()

            return {"message":"success"}, 200
        elif mode == "del":

            cur.execute(
                "DELETE FROM lost_and_found WHERE id=?",
                (torem,)
            )

            conn.commit()
            conn.close()

            return {"message":"success"}, 200

############################################################
# ADMIN
############################################################

class SetPIN(Resource):

    def post(self):
        args = request.json

        newpin = args.get("pin")
        newpinuser = args.get("user")

        token = args.get("token","")

        session = _session_valid(token)

        if session is None:
            return {"message":"error"}, 401

        if session["user"] != "admin":
            return {"message":"error"}, 403

        conn = db()
        cur = conn.cursor()

        try:
            cur.execute(
                """
                UPDATE users_accounts
                SET pin_hash=?
                WHERE role=?
                """,
                (
                    generate_password_hash(newpin),
                    newpinuser
                )
            )

            conn.commit()
            conn.close()

            return {"message":"success"}

        except:
            conn.close()
            return {"message":"error"}, 500

############################################################
# APPROVE ARTICLE
############################################################

class ApproveArticle(Resource):

    def post(self):
        args = request.json

        ata = args.get("ata","")
        mode = args.get("mode","0")

        modifiedart = args.get("modified",{})

        s = _session_valid(args.get("token",""))

        if s is None:
            return {"message":"unauthorized"},401

        if s["user"] != "admin":
            return {"message":"unauthorized"},401

        conn = db()
        cur = conn.cursor()

        if mode == '0':

            cur.execute(
                """
                UPDATE news_articles
                SET approved=1
                WHERE article_uid=?
                """,
                (ata,)
            )

        elif mode == '1':

            cur.execute(
                "DELETE FROM news_articles WHERE article_uid=?",
                (ata,)
            )

        elif mode == '2':

            cur.execute(
                """
                UPDATE news_articles
                SET
                    title=?,
                    content=?,
                    image_url=?,
                    author=?,
                    approved=1
                WHERE article_uid=?
                """,
                (
                    modifiedart.get("title",""),
                    modifiedart.get("content",""),
                    modifiedart.get("image",""),
                    modifiedart.get("by",""),
                    ata
                )
            )

        conn.commit()
        conn.close()

        return {"message":"success"}

############################################################
# WAITING ARTICLES
############################################################

class GetWaitingArticles(Resource):

    def post(self):
        args = request.json or {}

        token = args.get("token","")

        session = _session_valid(token)

        if not session:
            return {"message":"unauthorized"}, 401

        if session["user"] != "admin":
            return {"message":"unauthorized"}, 403

        conn = db()
        cur = conn.cursor(dictionary=True)

        cur.execute(
            """
            SELECT *
            FROM news_articles
            WHERE approved=0
            ORDER BY id DESC
            """
        )

        rows = cur.fetchall()

        conn.close()

        articles = {}

        for i, article in enumerate(rows, start=1):
            articles[str(i)] = {
                "id": article["article_uid"],
                "by": article["author"],
                "title": article["title"],
                "content": article["content"],
                "image": article["image_url"]
            }

        return {
            "message":"success",
            "articles":articles
        }
        
        
############################################################
# IDEAS
############################################################
class Idea(Resource):
    def post(self):
        args = request.json or {}

        token = args.get("token","")

        session = _session_valid(token)

        if not session:
            return {"message":"unauthorized"}, 401

        if session["user"] != "eleves":
            return {"message":"unauthorized"}, 403

        conn = db()
        
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """
            insert into idea values (?,?,?,?)
            """,
            (
                args["IP"],
                args["title"],
                args["content"],
                args["author"]
            )
        )
        conn.commit()

        conn.close()
        return {"message":"success"}
 
        
############################################################
# FORUM
############################################################


class LoginED1(Resource):
    def post(self):
        args = request.json or {}
        try:
            resp = requests.post("http://127.0.0.1:8080/login", json={
                "username": args.get("username", ""),
                "password": args.get("password", "")
            }, timeout=10)
            return resp.json(), resp.status_code
        except Exception as e:
            return {"success": False, "message": str(e)}, 502

class LoginED2(Resource):
    def post(self):
        args = request.json or {}
        try:
            resp = requests.post("http://127.0.0.1:8080/login/2fa", json={
                "username": args.get("username", ""),
                "password": args.get("password", ""),
                "cn": args.get("cn", ""),
                "cv": args.get("cv", ""),
                "x_token": args.get("x_token", ""),
                "twofa_token": args.get("twofa_token", ""),
                "gtk": args.get("gtk", "")
            }, timeout=10)
            return resp.json(), resp.status_code
        except Exception as e:
            return {"success": False, "message": str(e)}, 502

class ProxyImage(Resource):
    def get(self):
        target_url = request.args.get("url")
        if not target_url:
            return {"message": "URL manquante"}, 400

        if target_url.startswith("//"):
            target_url = "https:" + target_url

        try:
            # On simule un navigateur REEL pour pas se faire jeter
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
                "Accept-Language": "fr-FR,fr;q=0.9",
                "Referer": "https://www.ecoledirecte.com/", # On simule qu'on vient du site officiel
                "Connection": "keep-alive"
            }

            # On récupère l'image
            img_resp = requests.get(target_url, headers=headers, timeout=10, stream=True)

            if img_resp.status_code != 200:
                return {"message": f"ED a repondu {img_resp.status_code}"}, img_resp.status_code

            # On renvoie le flux binaire directement
            return Response(
                img_resp.content,
                mimetype=img_resp.headers.get('Content-Type', 'image/jpeg')
            )
        except Exception as e:
            return {"message": str(e)}, 502

def login_flarum_user(username, password):
    FLARUM_URL = "http://localhost/flarum-forum/api/token"
    headers = {"Content-Type": "application/json"}
    payload = {"identification": username, "password": password}

    try:
        response = requests.post(FLARUM_URL, json=payload, headers=headers, timeout=10)
    except Exception as e:
        return {"success": False, "error": str(e)}

    if response.status_code == 200:
        return {"success": True, "data": response.json()}
    else:
        return {"success": False, "error": response.text}


def create_flarum_user(username, email, password, group_id):
    FLARUM_URL = "http://localhost/flarum-forum/api/users"
    ADMIN_ID = 1

    headers = {
        "Authorization": f"Token {FLARUM_MASTER_API_KEY}; userId={ADMIN_ID}",
        "Content-Type": "application/json"
    }

    payload = {
        "data": {
            "type": "users",
            "attributes": {
                "username": username,
                "email": email,
                "password": password,
                "isEmailConfirmed": True
            }
        }
    }


    try:
        response = requests.post(FLARUM_URL, json=payload, headers=headers, timeout=10)
    except Exception as e:
        return {"success": False, "error": str(e)}

    if response.status_code == 201:
        # Assign tag
        user_id = response.json()["data"]["id"]
        group_url = f"{FLARUM_URL}/{user_id}/groups"
        group_payload = {
            "data": [
                {
                    "type": "groups",
                    "id": str(group_id)
                }
            ]
        }
        r = requests.post(group_url, json=group_payload, headers=headers, timeout=10)
        print(r.status_code)
        print(r.json())
        return {"success": True, "data": response.json()}
    else:
        return {"success": False, "error": response.text}


class LoginForum(Resource):
    def post(self):
        args = request.json or {}

        prenom = args.get("prenom", "")
        nom = args.get("nom", "")
        email = args.get("email", "")
        sexe = args.get("sexe", "")
        classe = args.get("classe", "")

        if not all([prenom, nom, email, sexe, classe]):
            return {"message": "missing_fields"}, 400

        flarum_username = f"{prenom}_{nom}".replace(" ", "")
        password = _derive_flarum_password(email, prenom, sexe, classe)

        result = login_flarum_user(flarum_username, password)

        if result["success"]:
            return {
                "token": result["data"].get("token"),
                "userId": result["data"].get("userId"),
                "firstTime": False
            }
        
        # Determiner groupid (tag classe)
        classe_num = classe[0] # par exemple "3F" --> "3"
        groupid = 0
        match classe_num:
            case '6':
                groupid = 5
            case '5':
                groupid = 6
            case '4':
                groupid = 7
            case '3':
                groupid = 8
            case _:
                print("Classe num does not have associable group",classe_num)
        print(classe_num, groupid)
        creation = create_flarum_user(flarum_username, email, password, groupid)

        if not creation["success"]:
            return {"message": "creation_failed", "error": creation["error"]}, 502

        relogin = login_flarum_user(flarum_username, password)

        if not relogin["success"]:
            return {"message": "relogin_failed", "error": relogin["error"]}, 502

        return {
            "token": relogin["data"].get("token"),
            "userId": relogin["data"].get("userId"),
            "firstTime": True
        }

class CreatePost(Resource):
    def post(self):
        args = request.json or {}

        content = args.get("content", "")
        discussion_id = args.get("discussion_id")
        flarum_token = args.get("flarum_token")
        flarum_user_id = args.get("flarum_user_id")

        if not content or not discussion_id or not flarum_token or not flarum_user_id:
            return {"message": "missing_fields"}, 400

        if flarum_user_id == 1: # Skip moderation si admin
            resp = requests.post(
                "https://slgplus.shares.zrok.io/flarum-forum/api/posts",
                headers=headers,
                json={
                    "data": {
                        "type": "posts",
                        "attributes": {"content": content},
                        "relationships": {
                            "discussion": {"data": {"type": "discussions", "id": discussion_id}}
                        }
                    }
                }
            )

            return resp.json(), resp.status_code

        moderation = _moderate_and_correct(content)

        if moderation["blocked"]:
            return {"message": "refused", "reason": moderation["reason"]}, 403

        content = moderation["corrected"]

        headers = {
            "Content-Type": "application/vnd.api+json",
            "Authorization": f"Token {flarum_token};userId={flarum_user_id}"
        }

        resp = requests.post(
            "https://slgplus.shares.zrok.io/flarum-forum/api/posts",
            headers=headers,
            json={
                "data": {
                    "type": "posts",
                    "attributes": {"content": content},
                    "relationships": {
                        "discussion": {"data": {"type": "discussions", "id": discussion_id}}
                    }
                }
            }
        )

        return resp.json(), resp.status_code


class CreateDiscussion(Resource):
    def post(self):
        args = request.json or {}

        title = args.get("title", "")
        content = args.get("content", "")
        tag_id = args.get("tag_id")
        flarum_token = args.get("flarum_token")
        flarum_user_id = args.get("flarum_user_id")

        if not title or not content or not tag_id or not flarum_token or not flarum_user_id:
            return {"message": "missing_fields"}, 400

        title_moderation = _moderate_and_correct(title)
        if title_moderation["blocked"]:
            return {"message": "refused", "reason": title_moderation["reason"]}, 403

        content_moderation = _moderate_and_correct(content)
        if content_moderation["blocked"]:
            return {"message": "refused", "reason": content_moderation["reason"]}, 403

        title = title_moderation["corrected"]
        content = content_moderation["corrected"]

        headers = {
            "Content-Type": "application/vnd.api+json",
            "Authorization": f"Token {flarum_token};userId={flarum_user_id}"
        }

        resp = requests.post(
            "https://slgplus.shares.zrok.io/flarum-forum/api/discussions",
            headers=headers,
            json={
                "data": {
                    "type": "discussions",
                    "attributes": {"title": title, "content": content},
                    "relationships": {"tags": {"data": [{"type": "tags", "id": tag_id}]}}
                }
            }
        )

        return resp.json(), resp.status_code

def _moderate_and_correct(content):
    prompt = (
        "Tu es moderateur et correcteur d'un forum scolaire francais (college/lycee) frequente par des ados.\n\n"
        "Le ton est volontairement decontracte : les eleves ecrivent en langage courant, "
        "avec un peu d'argot leger, quelques fautes d'orthographe, peu de ponctuation. "
        "C'EST NORMAL ET AUTORISE dans une certaine mesure.\n\n"
        "Bloque le message si il contient reellement :\n"
        "- des insultes ciblees, du harcelement, ou des menaces\n"
        "- un ton agressif ou hostile envers quelqu'un, meme sans insulte explicite\n"
        "- du contenu sexuel, violent ou choquant\n"
        "- du spam ou de la publicite\n"
        "- des informations personnelles identifiables (adresse, telephone, reseaux sociaux)\n"
        "- des informations pas adaptés a un public collégien (de la 6ème à la 3ème)\n"
        "- un message ecrit avec TROP d'abreviations/texto au point d'etre difficile a lire\n"
        "- des termes ou memes \"brainrot\"/internet absurdes (quoicoubeh, 67/69 en blague, "
        "skibidi, apagnan, sigma, rizz, etc.)\n"
        "- une insulte cachee formee par les majuscules ou les premieres lettres des mots "
        "(acrostiche), meme si le message semble innocent une fois lu normalement, a noter que ED est un acronyme et ne cache pas d'insultes. "
        "Exemple : \"Carre Orange Noir Ou ca Orange Nitrite\" cache le mot \"CONOCON\"/\"CON\" "
        "via ses majuscules. Verifie TOUJOURS les premieres lettres des mots capitalises "
        "de maniere inhabituelle (majuscule au milieu d'une phrase, sans raison grammaticale) "
        "pour detecter ce genre de contournement.\n\n"
        "IMPORTANT : le brainrot/memes n'est PAS une insulte, c'est une categorie a part. "
        "Ne confonds jamais les deux dans ta RAISON.\n\n"
        "Si autorise, corrige le message pour qu'il soit bien ecrit en francais correct, "
        "MAIS garde un ton naturel et chaleureux, pas robotique. Ne raccourcis jamais "
        "excessivement une phrase juste pour la 'nettoyer'. Interprete les abreviations "
        "d'approbation courantes (aze, azy, ouep, mouais, etc.) et reformule-les en francais "
        "correct et naturel, pas juste en les supprimant.\n"
        "Exemple : \"aze merci\" doit devenir \"D'accord, merci !\" (PAS juste \"Merci.\" "
        "qui est trop sec et perd le sens du message d'origine).\n"
        "Exemple : \"jsp trop ce que jen pense\" doit devenir \"Je ne sais pas trop ce que j'en pense.\"\n\n"
        "Si bloque, la RAISON doit etre ecrite comme un avertissement direct adresse a l'eleve. "
        "Exemples de ton a adopter selon le cas :\n"
        "- Insultes/harcelement : \"Ton message contient des insultes ! Des avertissements repetes entraineront des sanctions !\"\n"
        "- Insulte cachee (acrostiche/majuscules) : \"On a repere une insulte cachee dans les majuscules de ton message, ce genre de contournement n'est pas tolere !\"\n"
        "- Agressivite/violence : \"Ton message decrit ou encourage un comportement violent, ce n'est pas tolere ici. Si tu as un souci avec quelqu'un, parles-en a un adulte !\"\n"
        "- Contenu choquant : \"Ton message contient un contenu choquant, ce n'est pas tolere sur ce forum !\"\n"
        "- Spam/pub : \"Ton message ressemble a du spam ou de la publicite, merci de rester dans le sujet !\"\n"
        "- Infos personnelles : \"Attention, ne partage jamais d'informations personnelles sur le forum !\"\n"
        "- Trop d'abreviations : \"Ton message est trop abrege pour etre compris, merci d'ecrire de maniere plus claire !\"\n"
        "- Brainrot/memes genants : \"Ce forum ne permet pas de parler en termes genants ou de memes internet, merci de reformuler serieusement !\"\n"
        "Adapte le message au cas precis, garde le ton direct et l'exclamation, mais reste correct.\n\n"
        "Reponds EXACTEMENT dans ce format, rien d'autre avant ou apres :\n"
        "STATUT: OK ou BLOQUE\n"
        "RAISON: (l'avertissement direct adresse a l'eleve, uniquement si BLOQUE, sinon ecris juste -)\n"
        "MESSAGE: (le message corrige, uniquement si OK, sinon ecris juste -)\n\n"
        f"Message a analyser : \"{content}\""
    )
    api_key = _get_next_gemini_key()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent?key={api_key}"

    try:
        resp = requests.post(
            url,
            json={"contents": [{"parts": [{"text": prompt}]}]},
            timeout=10
        )
        data = resp.json()
        answer = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        print("GEMINI RAW:", answer)

        statut_match = re.search(r"STATUT:\s*(OK|BLOQUE)", answer, re.IGNORECASE)
        raison_match = re.search(r"RAISON:\s*(.+)", answer)
        message_match = re.search(r"MESSAGE:\s*(.+)", answer, re.DOTALL)

        statut = statut_match.group(1).upper() if statut_match else "OK"

        if statut == "BLOQUE":
            raison = raison_match.group(1).strip() if raison_match else "Ton message enfreint le reglement du forum !"
            return {"blocked": True, "reason": raison, "corrected": None}

        corrected = message_match.group(1).strip() if message_match else content
        corrected = corrected.strip('"').strip("'").strip('«»').strip()

        if not corrected or corrected == "-":
            corrected = content

        return {"blocked": False, "reason": None, "corrected": corrected}

    except Exception as e:
        print("GEMINI EXCEPTION:", repr(e))
        return {"blocked": False, "reason": None, "corrected": content}
############################################################
# API ROUTES
############################################################

api.add_resource(Ping, '/')

api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')

api.add_resource(CheckToken, '/checktoken')
api.add_resource(CheckEleves, '/checkeleves')

api.add_resource(News, '/news')
api.add_resource(CheckArticle, '/checkarticle')

api.add_resource(LostAndFound, '/lostandfound')

api.add_resource(Idea, '/idea')

api.add_resource(SetPIN,"/admin/setpin")
api.add_resource(ApproveArticle,"/admin/articles")
api.add_resource(GetWaitingArticles, "/admin/waitnews")

api.add_resource(LoginForum, "/forum/login/flarum")
api.add_resource(CreatePost, "/forum/post")
api.add_resource(CreateDiscussion, "/forum/discussion")

############################################################
# START
############################################################


if __name__ == "__main__":
    serve(app, host=CONFIG["server"]["host"], port=CONFIG["server"]["port"], threads=32)



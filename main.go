package main

import (
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/binary"
	"fmt"
	"html/template"
	"log"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var (
	//go:embed templates
	data      embed.FS
	templates = template.Must(template.ParseFS(data, "templates/*.html"))
)

type App struct {
	db             *sql.DB
	stmtLogin      *sql.Stmt
	stmtRegister   *sql.Stmt
	stmtNewSession *sql.Stmt
	stmtEndSession *sql.Stmt
	stmtGetSession *sql.Stmt
}

func initApp() (*App, error) {
	var app App
	var err error

	if app.db, err = sql.Open("sqlite", "db"); err != nil {
		return nil, err
	}

	// NOTE: "password" is actually a salted bcrypt hash
	_, err = app.db.Exec(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY NOT NULL,
            password TEXT NOT NULL
        )
    `)
	if err != nil {
		app.db.Close()
		return nil, err
	}

	_, err = app.db.Exec(`
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY NOT NULL,
            username TEXT NOT NULL
        )
    `) // FIXME: date field for expiration/cleanup
	if err != nil {
		app.db.Close()
		return nil, err
	}

	app.stmtLogin, err = app.db.Prepare(
		"SELECT password FROM users WHERE username = ?",
	)
	if err != nil {
		app.db.Close()
		return nil, err
	}

	app.stmtRegister, err = app.db.Prepare(
		"INSERT INTO users VALUES (?, ?)",
	)
	if err != nil {
		app.db.Close()
		return nil, err
	}

	app.stmtNewSession, err = app.db.Prepare(
		"INSERT INTO sessions VALUES (?, ?)",
	)
	if err != nil {
		app.db.Close()
		return nil, err
	}

	app.stmtEndSession, err = app.db.Prepare(
		"DELETE FROM sessions WHERE id = ?",
	)
	if err != nil {
		app.db.Close()
		return nil, err
	}

	app.stmtGetSession, err = app.db.Prepare(
		"SELECT username FROM sessions WHERE id = ?",
	)
	if err != nil {
		app.db.Close()
		return nil, err
	}

	return &app, nil
}

func generateSessionId() string {
	var raw [16]byte // 128-bit session ID
	rand.Read(raw[:])
	return fmt.Sprintf(
		"%016x%016x",
		binary.LittleEndian.Uint64(raw[0:]),
		binary.LittleEndian.Uint64(raw[8:]),
	)
}

func (app *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("%#v", r.URL.Path)

	// NOTE: disallow any framing by any origin (CRSF)
	w.Header().Set("x-frame-options", "DENY")

	var session, username string
	sessions := r.CookiesNamed("session")
	if len(sessions) > 0 {
		session = sessions[0].Value
		app.stmtGetSession.QueryRow(session).Scan(&username)
	}

	// FIXME: use a real mux
	if r.Method == "GET" && r.URL.Path == "/" {
		// passthrough

	} else if r.Method == "POST" && r.URL.Path == "/logout" {
		app.stmtEndSession.Exec(session)
		http.Redirect(w, r, "/", http.StatusFound)
		return

	} else if r.Method == "POST" && r.URL.Path == "/login" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var h string
		app.stmtLogin.QueryRow(username).Scan(&h)
		if bcrypt.CompareHashAndPassword([]byte(h), []byte(password)) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return // FIXME: report bad username or password
			// SECURITY NOTE: deliberately ambiguous about what failed!
		}

		id := generateSessionId()
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			HttpOnly: true,                    // no JavaScript access
			MaxAge:   60 * 60 * 24 * 90,       // ~3 months
			SameSite: http.SameSiteStrictMode, // instead of CSRF token
			Value:    id,
		})
		app.stmtNewSession.Exec(id, username)
		http.Redirect(w, r, "/", http.StatusFound)
		return

	} else if r.Method == "POST" && r.URL.Path == "/register" {
		username := r.FormValue("username")
		password := r.FormValue("password")
		hash, err := bcrypt.GenerateFromPassword([]byte(password), 0)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return // FIXME: handle long (>72) passwords
		}

		if _, err := app.stmtRegister.Exec(username, hash); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return // FIXME: report user already exists
		}

	} else {
		w.WriteHeader(http.StatusNotFound)
		templates.Lookup("404.html").Execute(w, nil)
		return
	}

	if len(username) > 0 {
		templates.Lookup("loggedin.html").Execute(w, map[string]string{
			"username": username,
		})
	} else {
		templates.Lookup("index.html").Execute(w, nil)
	}
}

func main() {
	app, err := initApp()
	if err != nil {
		log.Fatal(err)
	}

	s := &http.Server{
		Addr:    ":8080",
		Handler: app,
	}
	log.Fatal(s.ListenAndServe())
}

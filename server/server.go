package server

// TODO: Display errors from HTMX

// TODO: Write templates to buffer before to ResponseWriter in order to check
// for errors and avoid partial writes?

// TODO: Allow functions to be passed in for checking for uniqueness fails.
// This makes it more composable and aligns with being able to pass in a DB.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	chi "github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	jwtauth "github.com/go-chi/jwtauth/v5"
	cmtpkg "github.com/johnietre/ventit/comment"
	userpkg "github.com/johnietre/ventit/user"
	sqlite3 "github.com/mattn/go-sqlite3"
)

const (
  jwtCookieName = "ventit-jwt"
  anonymousUsername = "ANONYMOUS"
)

var (
  indexTmplName = "index"
	tmpls     = template.New("")

  errUsernameExists = fmt.Errorf("username exists")
  errEmailExists = fmt.Errorf("username exists")
  errUserNotExist = fmt.Errorf("user doesnt' exist")
)

func LoadIndexFile(file string) error {
  indexTmplName = filepath.Base(file)
  var err error
  tmpls, err = tmpls.ParseFiles(file)
  return err
}

func LoadTemplateFiles(filenames ...string) error {
	var err error
	tmpls, err = tmpls.ParseFiles(filenames...)
  return err
}

func LoadTemplateGlob(pattern string) error {
	var err error
  tmpls, err = tmpls.ParseGlob(pattern)
  return err
}

type handler struct {
	mux *chi.Mux
	db  *sql.DB
  tokenAuth *jwtauth.JWTAuth
}

const (
  testing = false
  //testing = true
)

func NewHandler(db *sql.DB, jwtKey string) http.Handler {
	mux := chi.NewRouter()
	if val := strings.ToLower(os.Getenv("REQ_LOG")); val == "on" || val == "1" {
		mux.Use(middleware.Logger)
	}
	h := &handler{
    mux: mux,
    db: db,
    tokenAuth: jwtauth.New("HS256", []byte(jwtKey), nil),
  }
  verifier := jwtauth.Verify(
    h.tokenAuth,
    jwtauth.TokenFromHeader,
    func(r *http.Request) string {
      cookie, err := r.Cookie(jwtCookieName)
      if err != nil {
        return ""
      }
      return cookie.Value
    },
  )
  mux.Use(verifier)
  mux.Get("/", h.HomeHandler)

  mux.Get("/login", h.LoginTmplHandler)
  mux.Post("/login", h.LoginHandler)

  mux.Get("/register", h.RegisterTmplHandler)
  mux.Post("/register", h.RegisterHandler)
  //mux.Post("/users", h.NewUserHandler)
  mux.Group(func(r chi.Router) {
    // TODO
    if !testing {
      r.Use(jwtauth.Authenticator)
    }
    r.Post("/logout", h.LogoutHandler)

    r.Get("/users/{id}", h.GetUserHandler)
    r.Delete("/users", h.DeleteUserHandler)

    r.Get("/comments", h.GetCommentsHandler)
    r.Post("/comments", h.PostCommentHandler)
    r.Delete("/comments/{id}", h.DeleteCommentHandler)
  })
	return h
}

func (s *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *handler) HomeHandler(w http.ResponseWriter, r *http.Request) {
  _, ok := userIdFromJWT(r)
  execTmpl(w, indexTmplName, struct{LoggedIn bool}{ok})
}

func (s *handler) LoginTmplHandler(w http.ResponseWriter, r *http.Request) {
  execTmpl(w, "login", nil)
}

func (s *handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
  r.ParseForm()
  email, pwd := r.Form.Get("email"), r.Form.Get("password")
  if email == "" || pwd == "" {
    writeErr(w, r, "bad request", http.StatusBadRequest)
    return
  }
  user, pwdHash, err := s.getUserByEmail(email)
  if err != nil {
    if err == errUserNotExist {
      writeErr(w, r, "invalid credentials", http.StatusBadRequest)
    } else {
      writeErr(w, r, "internal server error", http.StatusInternalServerError)
      log.Printf("error getting password hash for %s: %v", email, err)
    }
    return
  }
  if !userpkg.CheckPassword(pwd, pwdHash) {
    writeErr(w, r, "invalid credentials", http.StatusUnauthorized)
    return
  }
  tok, err := s.newJWTStr(user.Id)
  if err != nil {
    handleNewTokErr(w, r, user, err)
    return
  }
  setJWTCookie(w, tok)
  if acceptsHTML(r) {
    execTmpl(w, "home", nil)
    return
  }
  json.NewEncoder(w).Encode(newTokResp(user, tok))
}

func (s *handler) getUserByEmail(
  email string,
) (user userpkg.User, passwordHash string, err error) {
  row := s.db.QueryRow(
    `SELECT id,username,anonymous,password_hash FROM users WHERE email=?`,
    email,
  )
  err = row.Scan(&user.Id, &user.Username, &user.Anonymous, &passwordHash)
  if err != nil {
    if err == sql.ErrNoRows {
      err = errUserNotExist
    }
    return
  }
  user.Email = email
  return
}

func (s *handler) RegisterTmplHandler(w http.ResponseWriter, r *http.Request) {
  execTmpl(w, "register", nil)
}

func (s *handler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
  s.NewUserHandler(w, r)
}

func (s *handler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
  _, ok := userIdFromJWT(r)
  if !ok {
    writeErr(w, r, "unauthorized", http.StatusUnauthorized)
    return
  }
  http.SetCookie(
    w,
    &http.Cookie{
      Name: jwtCookieName,
      Value: "",
      MaxAge: -1,
    },
  )
  if acceptsHTML(r) {
    execTmpl(w, "login", nil)
  }
}

func (s *handler) NewUserHandler(w http.ResponseWriter, r *http.Request) {
  /*
	type Request struct {
		User     userpkg.User `json:"user"`
		Password string       `json:"password"`
	}
	var req Request
	user := req.User
  username := strings.ToLower(user.Username)
  */
  r.ParseForm()
  form := r.Form
  username := form.Get("username")
  if username == "" || username == anonymousUsername {
    writeErr(w, r, "invalid username", http.StatusBadRequest)
    return
  }
  email, password := form.Get("email"), form.Get("password")
  if email == "" || password == "" {
    writeErr(w, r, "invalid credentials", http.StatusBadRequest)
    return
  }
	pwdHash, err := userpkg.HashPassword(password)
	if err != nil {
    writeErr(w, r, "invalid credentials", http.StatusBadRequest)
    return
	}
  user := userpkg.User{
    Username: username,
    Email: email,
    Anonymous: form.Get("anonymous") != "",
  }
  if err := s.insertUser(&user, pwdHash); err != nil {
    if err == errUsernameExists {
      writeErr(w, r, "username already exists", http.StatusBadRequest)
    } else if err == errEmailExists {
      writeErr(w, r, "email already exists", http.StatusBadRequest)
    } else {
      writeErr(w, r, "internal server error", http.StatusInternalServerError)
      log.Print(err)
    }
    return
  }
  tok, err := s.newJWTStr(user.Id)
  if err != nil {
    handleNewTokErr(w, r, user, err)
    return
  }
  http.SetCookie(
    w,
    &http.Cookie{
      Name: jwtCookieName,
      Value: tok,
    },
  )
  if acceptsHTML(r) {
    execTmpl(w, "home", nil)
    return
  }
  json.NewEncoder(w).Encode(newTokResp(user, tok))
}

// Adds the ID to the passed user on success
func (s *handler) insertUser(user *userpkg.User, pwdHash string) error {
	stmt := `INSERT INTO users VALUES (?,?,?,1)`
	res, err := s.db.Exec(stmt, user.Username, user.Email, pwdHash)
	if err != nil {
    if errIsUnique(err) {
      // TODO: Make more composable (or something)?
      if strings.Contains(err.Error(), "username") {
        return errUsernameExists
      } else {
        return errEmailExists
      }
    }
    return fmt.Errorf(
      "error creating user for %s (username: %s): %v",
      user.Email, user.Username, err,
    )
	}
	id, err := res.LastInsertId()
	if err != nil {
    return fmt.Errorf(
      "error getting user id for %s (username: %s): %v",
      user.Email, user.Username, err,
    )
	}
	user.Id = uint64(id)
  return nil
}

func (s *handler) GetUserHandler(w http.ResponseWriter, r *http.Request) {
  userId, ok := userIdFromJWT(r)
  if !ok {
    writeErr(w, r, "unauthorized", http.StatusUnauthorized)
    return
  }
  user, err := s.getUserById(userId, userId)
  if err != nil {
    if err == errUserNotExist {
      writeErr(w, r, "user does not exist", http.StatusNotFound)
    } else {
      writeErr(w, r, "internal server error", http.StatusInternalServerError)
    }
    return
  }
  if acceptsHTML(r) {
    writeErr(w, r, "not implemented", http.StatusNotImplemented)
    return
  }
  json.NewEncoder(w).Encode(newOkResp().withUser(user))
}

func (s *handler) getUserById(userId, id uint64) (user userpkg.User, err error) {
  row := s.db.QueryRow(`SELECT username,email,anonymous FROM users WHERE id=?`, id)
  err = row.Scan(user.Username,user.Email,user.Anonymous)
  if err != nil {
    if err == sql.ErrNoRows {
      err = errUserNotExist
    }
    return
  }
  if userId == id {
    user.Id = id
  } else {
    user.Email = ""
    if user.Anonymous {
      user.Username = anonymousUsername
    }
  }
  return
}

func (s *handler) EditUserHandler(w http.ResponseWriter, r *http.Request) {
  writeErr(w, r, "not implemented", http.StatusNotImplemented)
}

func (s *handler) DeleteUserHandler(w http.ResponseWriter, r *http.Request) {
  writeErr(w, r, "not implemented", http.StatusNotImplemented)
}

type CommentsData struct {
  Comments []cmtpkg.Comment `json:"comments"`
  ParentId uint64 `json:"parentId"`
  LastId   uint64 `json:"lastId"`
  NextPage uint64 `json:"nextPage"`
  Error    string `json:"error"`
}

func (s *handler) GetCommentsHandler(w http.ResponseWriter, r *http.Request) {
  userId, ok := userIdFromJWT(r)
  if !ok {
    writeErr(w, r, "unauthorized", http.StatusUnauthorized)
    return
  }
	var err error
	vals := r.URL.Query()
	// lastId is the greatest (last) ID that will be included in the search
	var parentId, lastId, pageNum uint64
	if str := vals.Get("parent_id"); str != "" {
		if parentId, err = strconv.ParseUint(str, 10, 64); err != nil {
			http.Error(w, "invalid parent_id", http.StatusBadRequest)
			return
		}
	}
	if str := vals.Get("last_id"); str != "" {
		if lastId, err = strconv.ParseUint(str, 10, 64); err != nil {
			http.Error(w, "invalid last_id", http.StatusBadRequest)
			return
		}
	}
	if str := vals.Get("page"); str != "" {
		if pageNum, err = strconv.ParseUint(str, 10, 64); err != nil {
			http.Error(w, "invalid page", http.StatusBadRequest)
			return
		}
	}
  data, err := s.getCommentsData(userId, parentId, lastId, pageNum)
  if err != nil {
    log.Print(err)
    if data == nil {
      writeErr(w, r, "internal server error", http.StatusInternalServerError)
      return
    }
  }
  if acceptsHTML(r) {
    if err := tmpls.ExecuteTemplate(w, "comments", data); err != nil {
      log.Print("error executing template: ", err)
      http.Error(w, "Internal server error", http.StatusInternalServerError)
    }
    return
  }
  // TODO: What code to send on partial error?
  json.NewEncoder(w).Encode(newOkResp().withData(data))
}

func (s *handler) PostCommentHandler(w http.ResponseWriter, r *http.Request) {
    writeErr(w, r, "not implemented", http.StatusNotImplemented)
}

func (s *handler) DeleteCommentHandler(w http.ResponseWriter, r *http.Request) {
    writeErr(w, r, "not implemented", http.StatusNotImplemented)
}

func (s *handler) getCommentsData(
  userId, parentId, lastId, pageNum uint64,
) (*CommentsData, error) {
	const limit uint64 = 10
	var args []any
	stmt := `
  SELECT comments.id,users.id,users.username,users.anonymous,
         comments.content,comments.timestamp,comments.num_children
  FROM comments
  LEFT JOIN users
  ON comments.user_id = users.id
  -- Order by timestamp?
  WHERE parent_id = ?`
	if lastId != 0 {
		stmt += ` AND comments.id <= ?`
		args = []any{parentId, lastId, limit, pageNum * limit}
	} else {
		args = []any{parentId, limit, pageNum * limit}
	}
	stmt += `
  ORDER BY comments.id DESC
  LIMIT ?
  OFFSET ?
  `
	rows, err := s.db.Query(stmt, args...)
	if err != nil {
		// TODO: Change based on error returned
		return nil, fmt.Errorf("error querying db: %v", err)
	}
	data := &CommentsData{ParentId: parentId, LastId: lastId}

	comment := cmtpkg.Comment{ParentId: parentId}
	for rows.Next() {
    isAnonymous := false
		e := rows.Scan(
			&comment.Id, &comment.UserId, &comment.Username, &isAnonymous,
			&comment.Content, &comment.Timestamp, &comment.NumChildren,
		)
		if e != nil && err == nil {
			// Keep only the first encountered error
			err = e
			//data.Error = e.Error()
			continue
		}
		if comment.Id > data.LastId {
			data.LastId = comment.Id
		}
    if comment.UserId != userId && isAnonymous {
      comment.Username = anonymousUsername
    }
		data.Comments = append(data.Comments, comment)
	}
	if err != nil {
		err = fmt.Errorf("error querying db: %v", err)
    data.Error = "internal server error"
	} else if len(data.Comments) != 0 {
		data.NextPage = pageNum + 1
	}
  return data, err
}

func (s *handler) newJWTStr(userId uint64) (string, error) {
  const jwtExpiry = time.Hour * 24 * 14
  claims := map[string]any{
    "userId": strconv.FormatUint(userId, 10),
  }
  now := time.Now()
  jwtauth.SetIssuedAt(claims, now)
  jwtauth.SetExpiry(claims, now.Add(jwtExpiry))
  _, str, err := s.tokenAuth.Encode(claims)
  return str, err
}

func setJWTCookie(w http.ResponseWriter, tok string) {
  http.SetCookie(
    w,
    &http.Cookie{
      Name: jwtCookieName,
      Value: tok,
    },
  )
}

func userIdFromJWT(r *http.Request) (uint64, bool) {
  // TODO
  if testing {
    return 0, true
  }
  _, claims, err := jwtauth.FromContext(r.Context())
  if err != nil {
    return 0, false
  }
  idStr, ok := claims["userId"].(string)
  if !ok {
    return 0, false
  }
  id, err := strconv.ParseUint(idStr, 10, 64)
  if err != nil {
    return 0, false
  }
  return id, true
}

func handleNewTokErr(
  w http.ResponseWriter, r *http.Request, user userpkg.User, err error,
) {
  writeErr(w, r, "internal server error", http.StatusInternalServerError)
  log.Printf(
    "error creating JWT for %s (username: %s): %v",
    user.Email, user.Username, err,
  )
}

func acceptsHTML(r *http.Request) bool {
  return sort.StringSlice(r.Header.Values("Accept")).Search("text/html") != -1
}

func writeErr(
  w http.ResponseWriter, r *http.Request,
  msg string, status int,
) {
  if acceptsHTML(r) {
    http.Error(w, msg, status)
    return
  }
  json.NewEncoder(w).Encode(struct{
    Status int `json:"status"`
    Error string `json:"error"`
  }{
    Status: status,
    Error: msg,
  })
}

func execTmpl(w http.ResponseWriter, name string, data any) {
  if err := tmpls.ExecuteTemplate(w, name, data); err != nil {
    http.Error(w, "internal server error", http.StatusInternalServerError)
    log.Printf("error executing template %s: %v", name, err)
  }
}

func errIsUnique(err error) bool {
  return errors.Is(err, sqlite3.ErrConstraintUnique)
}

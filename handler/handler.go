package handler

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/julienschmidt/httprouter"

	hash "github.com/user/entry3/hash"

	s "github.com/user/entry3/structures"
)

var JWTKey = []byte("my_secret_key")
var username = "test"

//Index : Welcome page
func Index(w http.ResponseWriter, r *http.Request, us httprouter.Params) {
	fmt.Fprint(w, "WELCOMEEE!")
}

//ChangeNickname :Changes the nickname into the form input
func ChangeNickname(db *sql.DB) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

		//Check token
		if !(checkToken(w, r)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		var res s.Response
		err := json.NewDecoder(r.Body).Decode(&res)
		if err != nil || res.Nickname == "" {
			// Error handling
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Nickname change
		if !(queryChangeNickname(db, res)) {
			w.WriteHeader(http.StatusOK)
		}
		db.Close()
	}
}

// LoginHandler :Login page, takes in Username and Password
func LoginHandler(db *sql.DB) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

		var creds s.Credentials
		err := json.NewDecoder(r.Body).Decode(&creds)
		username = creds.Username

		if err != nil || creds.Username == "" || creds.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		passwordBool := checkPassword(db, w, creds)

		if !passwordBool {
			// Unauthorised access
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Login Sucess
		if !(generateToken(w, r, creds)) {
			return
		}

		fmt.Println("Login Sucessful")
		http.Redirect(w, r, "/login/sample", 301)
	}
}

//LoginSucess Display
func LoginSucess(db *sql.DB) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		if !(checkToken(w, r)) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		} else {
			w.WriteHeader(http.StatusOK)
		}

		prof := queryGetProfile(db, username)

		// Welcome page
		fmt.Fprint(w, "Login Sucessfull \n")
		hellomsg := "Hello " + username + "\n"
		fmt.Fprint(w, hellomsg)
		printProfile(w, prof)
	}
}

// SignUpHandler : handle sign up page
func SignUpHandler(db *sql.DB) func(http.ResponseWriter, *http.Request, httprouter.Params) {
	return func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		var prof s.Profile
		err := json.NewDecoder(r.Body).Decode(&prof)
		if err != nil || prof.Username == "" || prof.Password == "" || prof.Nickname == "" || prof.FirstName == "" || prof.LastName == "" || prof.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		querySignUp(w, db, prof)
	}
}

//Checks whether the corresponding password matches the username
func checkPassword(db *sql.DB, w http.ResponseWriter, creds s.Credentials) bool {

	txt, err := db.Begin()
	if err != nil {
		// Error handling
		fmt.Println(err)
	}

	//Getting password
	result, err := txt.Query("SELECT password FROM sample.tb WHERE username=" + creds.Username)
	if err != nil {
		// Error handling
		fmt.Println(err)
	}
	var passwordSQL string
	for result.Next() {
		if err := result.Scan(&passwordSQL); err != nil {
			w.WriteHeader(http.StatusOK)
		}
		return hash.ComparePasswords(passwordSQL, []byte(creds.Password))
	}
	db.Close()
	return false
}

// Checks whether the username exists in the database

func checkToken(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			// If the cookie is not set, return an unauthorized status
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		// For any other type of error, return a bad request status
		w.WriteHeader(http.StatusBadRequest)
		return false
	}

	// Get the JWT string from the cookie
	tknStr := c.Value

	// Initialize a new instance of `Claims`
	claims := &s.Claims{}

	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return JWTKey, nil
	})
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func generateToken(w http.ResponseWriter, r *http.Request, creds s.Credentials) bool {
	// Generate token
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &s.Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JWTKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return false
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	})
	return true
}

func printProfile(w http.ResponseWriter, prof s.Profile) {
	fmt.Fprint(w, "Username: "+prof.Username+"\n")
	fmt.Fprint(w, "Nickname: "+prof.Nickname+"\n")
	fmt.Fprint(w, "Firstname: "+prof.FirstName+"\n")
	fmt.Fprint(w, "Lastname: "+prof.LastName+"\n")
	fmt.Fprint(w, "Email: "+prof.Email+"\n")
}

func querySignUp(w http.ResponseWriter, db *sql.DB, prof s.Profile) {
	tx, err := db.Begin()
	defer db.Close()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}
	_ = tx
	//hashedPassword := hash.HashAndSalt([]byte(prof.Password))
	_, err = tx.Exec("INSERT INTO sample.tb VALUES (?,?,?,?,?,?);", prof.Username, prof.Password, prof.Nickname, prof.FirstName, prof.LastName, prof.Email)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
	}
}

func queryGetProfile(db *sql.DB, username string) s.Profile {
	txt, err := db.Begin()
	row, err := txt.Query("SELECT * FROM sample.tb WHERE username=" + "\"" + username + "\"")
	if err != nil {
		// Error handling
		fmt.Println(err)
	}
	var prof s.Profile
	for row.Next() {
		if err := row.Scan(&prof.Username, &prof.Password, &prof.Nickname, &prof.FirstName, &prof.LastName, &prof.Email); err != nil {
			fmt.Println(err)
		}
	}
	row.Close()
	return prof
}

func queryChangeNickname(db *sql.DB, res s.Response) bool {
	txt, err := db.Begin()
	_, err = txt.Exec("UPDATE sample.tb SET nickname=" + res.Nickname + " WHERE username=" + username)
	if err != nil {
		// Error handling
		fmt.Println(err)
		return false
	}
	return true
}

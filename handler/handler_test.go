package handler

import (
	"bytes"
	sql "database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock" //jwt
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/julienschmidt/httprouter"
	s "github.com/user/entry3/structures"
	//s
)

var db, _ = sql.Open("mysql", "")

// Index testing
func TestIndex(t *testing.T) {

	router := httprouter.New()
	router.GET("/", Index)

	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		fmt.Println(err)
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	expected := "WELCOMEEE!"
	if rr.Body.String() != expected {
		t.Errorf("Handler returned unexpected body : got %v want %v", rr.Body.String(), expected)
	}
}

// Login handler testing
func TestLoginHandler(t *testing.T) {

	// Mocking database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	sampleSQL1 := ("SELECT password FROM sample.tb WHERE username=" + "wilbert2")
	mock.ExpectBegin()
	rows := sqlmock.NewRows([]string{"password"}).AddRow("$2a$04$nxqlJ89u74aMtt1hfK0EA.au.ujXq8O3aTWSqsygmvedLFCtk5aae")
	mock.ExpectQuery(sampleSQL1).WillReturnRows(rows)

	// Valid entry
	router := httprouter.New()
	router.POST("/login", LoginHandler(db))
	sampleJson := "{ \"username\":\"wilbert2\",\"password\":\"123\" }"
	jsonstr := []byte(sampleJson)
	req, err := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonstr))
	if err != nil {
		t.Errorf("Request failed")
	}

	// Error 400
	sampleJson = "{}"
	jsonstr = []byte(sampleJson)
	req, err = http.NewRequest("POST", "/login", bytes.NewBuffer(jsonstr))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	//Error 401
	sampleJson = "{ \"username\":\"wilbert2\",\"password\":\"124\" }"
	jsonstr = []byte(sampleJson)
	req, err = http.NewRequest("POST", "/login", bytes.NewBuffer(jsonstr))
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	db.Close()
}

func TestLoginSucess(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	sampleSQL1 := ("SELECT * FROM sample.tb WHERE username=\"wilbert2\"")
	mock.ExpectBegin()
	rows := sqlmock.NewRows([]string{"username", "password", "nickname", "firstname", "lastname", "email"}).AddRow("wilbert2", "$2a$04$nxqlJ89u74aMtt1hfK0EA.au.ujXq8O3aTWSqsygmvedLFCtk5aae", "will", "wilbert", "terbwil", "123@gmail.com")
	mock.ExpectQuery(sampleSQL1).WillReturnRows(rows)

	// Error 401, for no cookies
	router := httprouter.New()
	router.GET("/", LoginSucess(db))
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Errorf("Error requesting")
	}
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	// Sucessful entry
	db, mock, err = sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()

	sampleSQL1 = ("SELECT * FROM sample.tb WHERE username=\"wilbert2\"")
	mock.ExpectBegin()
	rows = sqlmock.NewRows([]string{"username", "password", "nickname", "firstname", "lastname", "email"}).AddRow("wilbert2", "$2a$04$nxqlJ89u74aMtt1hfK0EA.au.ujXq8O3aTWSqsygmvedLFCtk5aae", "will", "wilbert", "terbwil", "123@gmail.com")
	mock.ExpectQuery(sampleSQL1).WillReturnRows(rows)

	//Generate token
	var creds s.Credentials
	creds.Username = "wilbert2"
	creds.Password = "123"
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &s.Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(JWTKey)
	cookie := &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	}

	router.GET("/login/sample", LoginSucess(db))
	req, err = http.NewRequest("GET", "/login/sample", nil)
	rr = httptest.NewRecorder()
	req.AddCookie(cookie)
	router.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

}

func TestChangeNickname(t *testing.T) {

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("UPDATE sample.tb SET nickname=newnickname WHERE username=wilbert2").WillReturnResult(sqlmock.NewResult(1, 1))
	router := httprouter.New()
	router.POST("/login/editprof", ChangeNickname(db))

	// Generate Cookie
	var creds s.Credentials
	creds.Username = "wilbert2"
	creds.Password = "123"
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &s.Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(JWTKey)
	cookie := &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
	}

	// Proper entry with cookie , 201
	sampleJson := "{ \"nickname\": \"newnickname\" }"
	jsonstr := []byte(sampleJson)
	req, err := http.NewRequest("POST", "/login/editprof", bytes.NewBuffer(jsonstr))
	rr := httptest.NewRecorder()
	req.AddCookie(cookie)
	if err != nil {
		t.Errorf("Request failed")
	}

	router.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Unauthorized : Error 401
	sampleJson = "{ \"nickname\": \"new\" }"
	jsonstr = []byte(sampleJson)
	req, err = http.NewRequest("POST", "/login/editprof", bytes.NewBuffer(jsonstr))
	rr = httptest.NewRecorder()
	if err != nil {
		t.Errorf("Request failed")
	}

	router.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}

	// Bad Request : Error 400

	sampleJson = "{}"
	jsonstr = []byte(sampleJson)
	req, err = http.NewRequest("POST", "/login/editprof", bytes.NewBuffer(jsonstr))
	rr = httptest.NewRecorder()
	req.AddCookie(cookie)
	if err != nil {
		t.Errorf("Request failed")
	}

	router.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}
	db.Close()
}

func TestSignUpHandle(t *testing.T) {

	// Proper entry
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	mock.ExpectBegin()
	query := "INSERT INTO sample.tb VALUES "
	mock.ExpectExec(query).WithArgs("testername1003", "123", "test", "firstname", "lastname", "test@gmail.com").WillReturnResult(sqlmock.NewResult(1, 1))

	sampleJson := "{ \"username\": \"testername1003\",\"password\": \"123\", \"nickname\":\"test\",\"firstname\": \"firstname\",\"lastname\":\"lastname\",\"email\":\"test@gmail.com\" }"
	jsonstr := []byte(sampleJson)
	req, err := http.NewRequest("POST", "/signup", bytes.NewBuffer(jsonstr))
	if err != nil {
		t.Errorf("Fail to input properly")
	}
	router := httprouter.New()
	router.POST("/signup", SignUpHandler(db))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
	db.Close()

	// Primary key test,  expected Bad Request
	db, mock, err = sqlmock.New()
	if err != nil {
		t.Errorf("an error '%s' was not expected when opening a stub database connection", err)
	}
	defer db.Close()
	mock.ExpectBegin()
	query = "INSERT INTO sample.tb VALUES "
	mock.ExpectExec(query).WithArgs("wilbert2", "123", "test", "test", "lastname", "test@gmail.com").WillReturnError(fmt.Errorf("Invaid Primary Key"))

	sampleJson = "{ \"username\": \"wilbert2\",\"password\": \"123\", \"nickname\":\"test\",\"firstname\": \"test\",\"lastname\":\"lastname\",\"email\":\"test@gmail.com\" }"
	jsonstr = []byte(sampleJson)
	req, err = http.NewRequest("POST", "/signup", bytes.NewBuffer(jsonstr))
	if err != nil {
		t.Errorf("Fail to input properly")
	}
	router = httprouter.New()
	router.POST("/signup", SignUpHandler(db))
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Handler returned wrong status code true : got %v want %v", status, http.StatusBadRequest)
	}
	db.Close()
}

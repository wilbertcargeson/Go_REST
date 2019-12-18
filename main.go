package main

import (
	sql "database/sql"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
	"github.com/julienschmidt/httprouter"
	handler "github.com/user/entry3/handler"
)

var sqlLogin = "root:papamama@tcp(localhost:3306)/sample"

func main() {
	db, _ := sql.Open("mysql", sqlLogin)

	router := httprouter.New()
	router.GET("/", handler.Index)
	router.POST("/login", handler.LoginHandler(db))
	router.GET("/login/sample", handler.LoginSucess(db))
	router.POST("/login/editprof", handler.ChangeNickname(db))
	router.POST("/signup", handler.SignUpHandler(db))

	log.Fatal(http.ListenAndServe(":8080", router))

	db.Close()
}

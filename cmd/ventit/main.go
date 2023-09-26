package main

import (
	"database/sql"
	"flag"
	"log"
	"net/http"
	//"os"
	"strings"

	"github.com/johnietre/ventit/server"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
  log.SetFlags(0)

  tmplGlob := flag.String(
    "tmpl-glob", "templates/*.tmpl",
    "Glob pattern for templates (specify this or tmplFiles)",
  )
  tmplFiles := flag.String(
    "tmpl-files", "",
    "Comma-seperated list of template files (specify this or tmplFiles, takes preference)",
  )
  jwtKey := flag.String("jwt-key", "", "Key to sign JWTs with")
  indexPath := flag.String("index", "./index.html", "Path to index file")
  addr := flag.String("addr", "127.0.0.1:8000", "Address to run on")
  dbPath := flag.String("db-path", "", "Path to database")
  dbDriver := flag.String("db-driver", "sqlite3", "Database driver")
  flag.Parse()

  if *jwtKey == "" {
    log.Fatal("must provide JWT key")
  }

  db, err := sql.Open(*dbDriver, *dbPath)
  if err != nil {
    log.Fatal("error opening database: ", err)
  }

  if *tmplFiles != "" {
    err = server.LoadTemplateFiles(strings.Split(*tmplFiles, ",")...)
  }
  if err != nil {
    log.Fatal("error loading template files: ", err)
  }
  if *tmplGlob != "" {
    err = server.LoadTemplateGlob(*tmplGlob)
  }
  if err != nil {
    log.Fatal("error loading glob templates: ", err)
  }

  if err = server.LoadIndexFile(*indexPath); err != nil {
    log.Fatal("could not open index file")
  }

  log.Print("Serving on ", *addr)
  log.Fatal(
    http.ListenAndServe(*addr, server.NewHandler(db, *jwtKey)),
  )
}

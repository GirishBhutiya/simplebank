package main

import (
	"database/sql"
	"log"

	"github.com/GirishBhutiya/simplebank/api"
	db "github.com/GirishBhutiya/simplebank/db/sqlc"
	"github.com/GirishBhutiya/simplebank/util"
	_ "github.com/lib/pq"
)

func main() {
	config, err := util.LoadConfig(".")
	if err != nil {
		log.Fatalln("Can not load config:", err)
	}

	conn, err := sql.Open(config.DBDriver, config.DBSource)
	if err != nil {
		log.Fatalln("Can not connect to db:", err)
	}

	store := db.NewStore(conn)
	server, err := api.NewSerer(config, store)
	if err != nil {
		log.Fatalln("Can not create server:", err)
	}
	err = server.Start(config.ServerAddress)

	if err != nil {
		log.Fatalln("Can not start server:", err)
	}
}

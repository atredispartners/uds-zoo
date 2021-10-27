package main

import (
	"github.com/atredispartners/uds-zoo/uds/controller"
	"github.com/tidwall/buntdb"
)

func main() {
	db, err := buntdb.Open("data.db")
	if err != nil {
		panic(err)
	}
	app := controller.New(&controller.Opts{
		DB: db,
	})

	app.Start(":8888")
}

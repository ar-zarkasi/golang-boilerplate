package main

import (
	"app/router"
	"log"
	"os"
)

func main() {
	port := ":"+os.Getenv("PORT")
	routers := router.GetRouter()
	log.Fatal(routers.Run(port))
}
package main

import (
	"app/router"
	"fmt"
	"log"
	"os"
)

func main() {
	port := ":"+os.Getenv("PORT")
	routers := router.GetRouter()
	log.Fatal(routers.Run(port))
	fmt.Println("Server is running on port", port)
}
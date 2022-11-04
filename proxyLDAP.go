package main

import (
	"fmt"
	"log"
	"proxyldap/ldap"
	"proxyldap/mapstore"
)

func main() {

	fmt.Print("Iniciando proxy...\n")

	be := mapstore.MapstoreBackend

	fmt.Print("Conectando backend...\n")
	srv, err := ldap.NewServer(be, nil)
	if err != nil {
		fmt.Println("No se puedo conectar al backend.")
		log.Fatalln(err)
	}
	fmt.Print("Backend conectado.\n")

	fmt.Println("Sirviendo backend")
	err = srv.Serve("tcp", "127.0.0.1:389")
	if err != nil {
		fmt.Println("No se pudo servir el backend")
		log.Fatalln(err)
	}

}

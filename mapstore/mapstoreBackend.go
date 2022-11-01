package mapstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	. "proxyldap/ldap"
	"strings"

	_ "github.com/lib/pq"
)

type mapstoreBackend struct{}

var MapstoreBackend Backend = mapstoreBackend{}

var servLdap = "10.1.1.25:389"
var pgHost = "10.2.2.64"
var pgPort = "5432"
var pgUser = "postgres"
var pgPass = "lajirafaloca"
var pgDbName = "sigbd"
var baseDN = "ou=Users,dc=imcanelones,dc=gub,dc=uy"

func (mapstoreBackend) Add(ctx context.Context, state State, req *AddRequest) (*AddResponse, error) {
	fmt.Printf("ADD %+v\n", req)
	return &AddResponse{}, nil
}

func (mapstoreBackend) Bind(ctx context.Context, state State, req *BindRequest) (*BindResponse, error) {

	fmt.Printf("BIND %+v\n", req)

	c, err := Dial("tcp", servLdap)
	if err != nil {
		return nil, err
	}

	////////////////
	log.Println("Pasa dial")
	/* Antes del bind encontrar DN */

	usrDN, err := getUserDn(ctx, state, req)
	log.Println("Pasa getUserDN: " + usrDN)
	//////////////

	if err := c.Bind(usrDN, req.Password); err != nil {
		return nil, err
	}
	log.Println("Pasa Bind")
	return &BindResponse{
		BaseResponse: BaseResponse{
			Code:      ResultSuccess,
			MatchedDN: "",
			Message:   "",
		},
	}, nil
}

func (mapstoreBackend) Connect(remoteAddr net.Addr) (State, error) {
	return nil, nil
}

func (mapstoreBackend) Disconnect(state State) {
}

func (mapstoreBackend) Delete(ctx context.Context, state State, req *DeleteRequest) (*DeleteResponse, error) {
	fmt.Printf("DELETE %+v\n", req)
	return &DeleteResponse{}, nil
}

func (mapstoreBackend) ExtendedRequest(ctx context.Context, state State, req *ExtendedRequest) (*ExtendedResponse, error) {
	fmt.Printf("EXTENDED %+v\n", req)
	return nil, ProtocolError("unsupported extended request")
}

func (mapstoreBackend) Modify(ctx context.Context, state State, req *ModifyRequest) (*ModifyResponse, error) {
	fmt.Printf("MODIFY dn=%s\n", req.DN)
	for _, m := range req.Mods {
		fmt.Printf("\t%s %s\n", m.Type, m.Name)
		for _, v := range m.Values {
			fmt.Printf("\t\t%s\n", string(v))
		}
	}
	return &ModifyResponse{}, nil
}

func (mapstoreBackend) ModifyDN(ctx context.Context, state State, req *ModifyDNRequest) (*ModifyDNResponse, error) {
	fmt.Printf("MODIFYDN %+v\n", req)
	return &ModifyDNResponse{}, nil
}

func (mapstoreBackend) PasswordModify(ctx context.Context, state State, req *PasswordModifyRequest) ([]byte, error) {
	fmt.Printf("PASSWORD MODIFY %+v\n", req)
	return []byte("genpass"), nil
}

func (mapstoreBackend) Search(ctx context.Context, state State, req *SearchRequest) (*SearchResponse, error) {

	fmt.Printf("SEARCH %+v\n", req)

	//////////////

	res, err := forwardSearch(req)
	if err != nil {
		log.Fatal(err)
	}

	//////////////////

	return &SearchResponse{
		BaseResponse: BaseResponse{
			Code:      ResultSuccess, //LDAPResultNoSuchObject,
			MatchedDN: "",            //res.DN,
			Message:   "",
		},
		Results: res,
	}, nil
}

func (mapstoreBackend) Whoami(ctx context.Context, state State) (string, error) {
	fmt.Println("WHOAMI")
	return "cn=someone,o=somewhere", nil
}

func forwardSearch(req *SearchRequest) ([]*SearchResult, error) {

	debugCondition := req.BaseDN == "ou=Users,dc=imcanelones,dc=gub,dc=uy" && req.Scope == 2 && req.DerefAliases == 3 && req.SizeLimit == 0 && req.TimeLimit == 0 && !req.TypesOnly && strings.HasPrefix(req.Filter.String(), "(uid=")

	if debugCondition {
		// Query a la base
		psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", pgHost, pgPort, pgUser, pgPass, pgDbName)
		DB, err := sql.Open("postgres", psqlInfo)
		if err != nil {
			log.Fatalf("Error al conectarse a la base: %s", err)
		}

		nombreApellido := extractUsername(req.Filter.String())

		fmt.Println("Usuario nombre.apellido:" + nombreApellido)

		sql := "SELECT * FROM public.proxy_ldap_esquemas_usuario('" + nombreApellido + "') ORDER BY cn"
		data, err := DB.Query(sql)
		if err != nil {
			log.Fatalf("Error query: %s", err)
		}

		// SQL Result to LDAPResult
		//fmt.Print("Mi resultado de query\n")
		sqlRToldapResult(data)

		//fmt.Print(data)

		return nil, nil
	} else {
		// Query a LDAP
		c, err := Dial("tcp", servLdap)
		if err != nil {
			log.Fatal(err)
		}

		res, err := c.Search(req)

		if err != nil {
			log.Fatal(err)
		} else {
			for _, r := range res {

				fmt.Println("\nResult Print: ")
				//fmt.Printf("%+v\n", r) //con %c imprime los caracteres pero con espacios, tengo que ver bien eso para obtener el campo c[omo corresponde]
				r.ToLDIF(os.Stdout)

			}

		}

		return res, nil
	}
}

func getUserDn(ctx context.Context, state State, bReq *BindRequest) (string, error) {
	var sReq SearchRequest

	sReq.BaseDN = "ou=Users,dc=imcanelones,dc=gub,dc=uy"
	sReq.Scope = ScopeWholeSubtree
	sReq.DerefAliases = DerefAlways
	sReq.SizeLimit = 0
	sReq.TimeLimit = 0
	sReq.TypesOnly = false

	log.Println("Asigna variables a sReq")

	usr := extractUsername(bReq.DN)
	if usr == "" {
		return "", errors.New("No se pudo extraer el nombre de usuario")
	}

	log.Println("Usuario: " + usr)

	filter, err := ParseFilter(fmt.Sprintf("(uid=%s)", usr))
	if err != nil {
		return "", err
	}

	sReq.Filter = filter

	c, err := Dial("tcp", servLdap)
	if err != nil {
		log.Fatal(err)
	}

	res, err := c.Search(&sReq)
	ret := ""
	if err != nil {
		log.Fatal(err)
	} else {
		for _, r := range res {

			fmt.Println("\nResult Print: ")
			//fmt.Printf("%+v\n", r) //con %c imprime los caracteres pero con espacios, tengo que ver bien eso para obtener el campo c[omo corresponde]
			r.ToLDIF(os.Stdout)
			bandera := false
			if !bandera {
				ret = r.DN
				bandera = true
			}

		}

	}

	fmt.Println("DN usuario: " + ret)

	return ret, nil
}

func extractUsername(str string) (result string) {

	fmt.Println("String: " + str)

	start := "uid="
	end1 := ","
	end2 := ")"
	e := -1

	s := strings.Index(str, start)
	if s == -1 {
		return
	}

	s += len(start)

	e1 := strings.Index(str[s:], end1)
	e2 := strings.Index(str[s:], end2)

	if e1 == -1 && e2 == -1 {
		return
	}

	if e1 != -1 && e2 != -1 {
		if e1 < e2 {
			e = e1
		} else {
			e = e2
		}
	} else if e1 != -1 {
		e = e1
	} else if e2 != -1 {
		e = e2
	} else {
		return
	}

	e += s

	return str[s:e]
}

func sqlRToldapResult(rows *sql.Rows) { //([]*SearchResult, error) {

	cols, _ := rows.Columns()
	m := make(map[string]interface{})

	for rows.Next() {
		// Crear un slice de interface{} para representar cada columna
		// y un segundo slice para contener los punteros para cada item en la slice de columna
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))

		for i, _ := range columns {
			columnPointers[i] = &columns[i]
		}

		// Escanea el resultado en la columna de punteros
		if err := rows.Scan(columnPointers...); err != nil {
			return //nil, err
		}

		// Crear el mapa y devolver el valor por cada columna del slice de punteros
		// almacenandolos en el mapa con el nombre de la columna como key
		//m := make(map[string]interface{})
		for i, colName := range cols {
			val := columnPointers[i].(*interface{})
			m[colName] = *val
		}

	}

	// Salidas: map[columnName:value columnName2:value2 columnName3:value3...]
	fmt.Println(m)
	//var ret *SearchResult

	//ret.Attributes = m

	return //nil, nil
}

package mapstore

import (
	"bytes"
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

var ldapIC = "10.1.1.25:389"
var proxyLdappy = "127.0.0.1:10389"

var servLdap = proxyLdappy

var pgHost = "10.2.2.64"
var pgPort = "5432"
var pgUser = "postgres"
var pgPass = "lajirafaloca"
var pgDbName = "sigbd"
var baseDN = "ou=Users,dc=imcanelones,dc=gub,dc=uy"

func (mapstoreBackend) Add(ctx context.Context, state State, req *AddRequest) (*AddResponse, error) {
	//fmt.Printf("ADD %+v\n", req)
	log.Printf("ADD %+v\n", req)
	return &AddResponse{}, nil
}

func (mapstoreBackend) Bind(ctx context.Context, state State, req *BindRequest) (*BindResponse, error) {

	log.Printf("BIND req => %+v\n", req)
	usr, err := extractUsername(req.DN)
	if usr == "admin" {
		pas, err := obtenerPassAdmin()
		if err != nil {
			return nil, err
		}

		if string(req.Password) == pas {
			return &BindResponse{
				BaseResponse: BaseResponse{
					Code:      ResultSuccess,
					MatchedDN: "",
					Message:   "",
				},
			}, nil
		} else {
			return nil, errors.New("Contaseña incorrecta")
		}
	}

	c, err := Dial("tcp", servLdap)
	if err != nil {
		return nil, err
	}

	////////////////
	/* Antes del bind encontrar DN */

	usrDN, err := getUserDn(ctx, state, req)
	if err != nil {
		return nil, err
	}

	//////////////

	if err := c.Bind(usrDN, req.Password); err != nil {
		return nil, err
	}

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
	log.Printf("DELETE %+v\n", req)
	return &DeleteResponse{}, nil
}

func (mapstoreBackend) ExtendedRequest(ctx context.Context, state State, req *ExtendedRequest) (*ExtendedResponse, error) {
	log.Printf("EXTENDED %+v\n", req)
	return nil, ProtocolError("unsupported extended request")
}

func (mapstoreBackend) Modify(ctx context.Context, state State, req *ModifyRequest) (*ModifyResponse, error) {
	log.Printf("MODIFY dn=%s\n", req.DN)
	for _, m := range req.Mods {
		log.Printf("\t%s %s\n", m.Type, m.Name)
		for _, v := range m.Values {
			log.Printf("\t\t%s\n", string(v))
		}
	}
	return &ModifyResponse{}, nil
}

func (mapstoreBackend) ModifyDN(ctx context.Context, state State, req *ModifyDNRequest) (*ModifyDNResponse, error) {
	log.Printf("MODIFYDN %+v\n", req)
	return &ModifyDNResponse{}, nil
}

func (mapstoreBackend) PasswordModify(ctx context.Context, state State, req *PasswordModifyRequest) ([]byte, error) {
	log.Printf("PASSWORD MODIFY %+v\n", req)
	return []byte("genpass"), nil
}

func (mapstoreBackend) Search(ctx context.Context, state State, req *SearchRequest) (*SearchResponse, error) {

	log.Printf("SEARCH req => %+v\n", req)

	//////////////

	res, err := forwardSearch(req)
	if err != nil {
		log.Fatal(err)
	}

	for i, _ := range res {
		//fmt.Println("DEBUG SEARCH result => ")
		res[i].ToLDIF(os.Stdout)
	}

	//fmt.Printf("DEBUG SEARCH results => %v\n", res)

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
	log.Println("WHOAMI")
	return "cn=someone,o=somewhere", nil
}

// Se consulta si hay que reenviar la consulta a la BD o LDAP
func forwardSearch(req *SearchRequest) ([]*SearchResult, error) {

	log.Printf("FORWARD SEARCH req => %+v\n", req)
	sqlReq := false
	debugDB := false // Bandera para activar o desactivar la BD
	sqlQuery := ""
	groupsQuery := false

	//fmt.Printf("DEBUG FORWARDSEARCH filter => %v\n", req.Filter.String())

	// Si pregunta por todos los datos del usuario, se filtran solo algunos
	if (req.BaseDN == "ou=Users,dc=imcanelones,dc=gub,dc=uy" && req.Scope == 2 && req.DerefAliases == 3 && req.SizeLimit == 0 && req.TimeLimit == 0 && !req.TypesOnly && strings.HasPrefix(req.Filter.String(), "(uid=")) ||
		(req.BaseDN == "ou=Users,dc=imcanelones,dc=gub,dc=uy" && req.Scope == 2 && req.DerefAliases == 0 && req.SizeLimit == 0 && req.TimeLimit == 0 && !req.TypesOnly && strings.HasPrefix(req.Filter.String(), "(&(uid=") && strings.Contains(req.Filter.String(), "(objectClass=inetOrgPerson)")) {

		req.Attributes["dn"] = true
		req.Attributes["sn"] = true
		req.Attributes["uid"] = true
		req.Attributes["cn"] = true
		req.Attributes["displayName"] = true
		req.Attributes["objectClass"] = true
		req.Attributes["mail"] = true
		req.Attributes["employeeNumber"] = true
		req.Attributes["ou"] = true
	}

	// Si pregunta por los grupos de un usuario se consulta la BD
	if req.BaseDN == "ou=Groups,dc=imcanelones,dc=gub,dc=uy" && req.Scope == 2 && req.DerefAliases == 3 && req.SizeLimit == 0 && req.TimeLimit == 0 && !req.TypesOnly && (strings.HasPrefix(req.Filter.String(), "(memberUid=") || strings.HasPrefix(req.Filter.String(), "(member=uid")) {

		sqlReq = true
		groupsQuery = true

		usr, err := extractUsername(req.Filter.String())
		if err != nil {
			log.Fatalln(err)
		}

		sqlQuery = fmt.Sprintf("SELECT * FROM public.proxy_ldap_esquemas_usuario('%v') ORDER BY cn", usr)
		//fmt.Println("DEBUG FORWARDSEARCH sqlQuery => " + sqlQuery)

		//fmt.Println("DEBUG FORWARDSEARCH username => " + usr)

		newFilter, err := ParseFilter(fmt.Sprintf("(memberUid=%s)", usr))

		if err != nil {
			return nil, err
		}

		req.Filter = newFilter

		//fmt.Println("DEBUG FORWARDSEARCH filter repaired => " + newFilter.String())
	}

	// Consultas a la DB
	if sqlReq && debugDB {
		// Query a la base
		psqlInfo := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable", pgHost, pgPort, pgUser, pgPass, pgDbName)
		DB, err := sql.Open("postgres", psqlInfo)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error al conectarse a la base: %s", err))
		}

		data, err := DB.Query(sqlQuery)
		if err != nil {
			log.Fatalf("Error query: %s", err)
		}

		// SQL Result to LDAPResult
		rets, err := sqlRToldapResult(data)
		if err != nil {
			return nil, err
		}

		// Si la consulta fue de grupos se le agrega al DN a la respuesta
		if groupsQuery {
			for i, res := range rets {
				rets[i].DN = strings.Replace(strings.Replace(fmt.Sprintf("cn=%s,ou=Groups,dc=imcanelones,dc=gub,dc=uy", res.Attributes["cn"]), "[", "", -1), "]", "", -1)
			}
		}

		return rets, nil

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

				log.Printf("FORWARD SEARCH result => ")
				fmt.Printf("%+v\n", r) // se imprimen en formato binario
				//r.ToLDIF(os.Stdout) // se imprimen en formato string

			}

		}

		return res, nil
	}

}

func getUserDn(ctx context.Context, state State, bReq *BindRequest) (string, error) {
	log.Printf("GET USER DN req => %v", bReq)
	var sReq SearchRequest

	sReq.BaseDN = "ou=Users,dc=imcanelones,dc=gub,dc=uy"
	sReq.Scope = ScopeWholeSubtree
	sReq.DerefAliases = DerefAlways
	sReq.SizeLimit = 0
	sReq.TimeLimit = 0
	sReq.TypesOnly = false
	sReq.Attributes = make(map[string]bool)
	sReq.Attributes["dn"] = true

	usr, err := extractUsername(bReq.DN)
	if err != nil {
		return "", err
	}

	log.Printf("GET USER DN User => %v", usr)

	filter, err := ParseFilter(fmt.Sprintf("(uid=%s)", usr))
	if err != nil {
		return "", err
	}

	sReq.Filter = filter

	c, err := Dial("tcp", ldapIC)
	if err != nil {
		return "", err
	}

	res, err := c.Search(&sReq)
	ret := ""
	if err != nil {
		return "", err
	} else {
		for _, r := range res {
			buf := new(bytes.Buffer)
			//fmt.Println("\nResult Print: ")
			//fmt.Printf("%+v\n", r) //con %c imprime los caracteres pero con espacios, tengo que ver bien eso para obtener el campo c[omo corresponde]
			r.ToLDIF(buf)
			fmt.Printf("DEBUG GET USER DN => ")
			r.ToLDIF(os.Stdout)
			if buf.String() != "" && buf.String() != "[]" {
				//ret = fmt.Sprint(r.Attributes["dn"])

				ret = strings.Replace(buf.String(), "dn: ", "", -1)
			}

		}

	}

	log.Printf("GET USER DN dn => %v", ret)

	return ret, nil
}

func extractUsername(str string) (string, error) {

	log.Printf("EXTRACT USERNAME str => %v\n", str)

	if len(str) < 5 {
		return "", nil
	}

	start := "uid="
	start2 := "uid\\3d"
	end1 := ","
	end2 := ")"
	e := -1

	s := strings.Index(str, start)
	if s == -1 {
		s = strings.Index(str, start2)
		if s == -1 {
			return "", errors.New("EXTRACT USERNAME => No se encontro uid")
		} else {
			s += len(start2)
		}
	} else {
		s += len(start)
	}

	e1 := strings.Index(str[s:], end1)
	e2 := strings.Index(str[s:], end2)

	if e1 == -1 && e2 == -1 {
		return "", errors.New("EXTRACT USERNAME => No se encontro cierre de substring")
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
		return "", errors.New("EXTRACT USERNAME => No se pudo extraer el usuario")
	}

	e += s

	return str[s:e], nil
}

/*
func sqlRToldapResult(rows *sql.Rows) ([]*SearchResult, error) {

		cols, _ := rows.Columns()

		m := make(map[string]interface{})
		attrMap := make(map[string][][]byte)

		for rows.Next() {

			columns := make([]interface{}, len(cols))

			columnPointers := make([]interface{}, len(cols))

			for i, _ := range columns {
				columnPointers[i] = &columns[i]
			}

			if err := rows.Scan(columnPointers...); err != nil {
				return nil, err
			}

			for i, colName := range cols {
				val := columnPointers[i].(*interface{})
				m[colName] = *val
				attrMap[colName] = append(attrMap[colName], []byte(fmt.Sprint(m[colName])))
			}

		}

		//fmt.Println("DEBUG SQLTOLDAP row => ")
		fmt.Println(attrMap)

		var newSR *SearchResult
		newSR = new(SearchResult)
		newSR.Attributes = attrMap

		var ret []*SearchResult

		//fmt.Println("DEBUG SQLTOLDAP newSR => ")
		newSR.ToLDIF(os.Stdout)

		ret = append(ret, newSR)

		//fmt.Printf("DEBUG SQLTOLDAP ret => %v\n", ret)
		//fmt.Printf("DEBUG SQLTOLDAP ret[0].Attributes => %v\n", ret[0].Attributes)

		return ret, nil
	}
*/
func sqlRToldapResult(rows *sql.Rows) ([]*SearchResult, error) {

	var ret []*SearchResult

	cols, _ := rows.Columns()

	m := make(map[string]interface{})

	for rows.Next() {

		columns := make([]interface{}, len(cols))

		columnPointers := make([]interface{}, len(cols))

		for i, _ := range columns {
			columnPointers[i] = &columns[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			return nil, err
		}

		var newSR *SearchResult
		newSR = new(SearchResult)
		newSR.Attributes = make(map[string][][]byte)

		for i, colName := range cols {
			val := columnPointers[i].(*interface{})
			m[colName] = *val
			newSR.Attributes[colName] = append(newSR.Attributes[colName], []byte(fmt.Sprint(m[colName])))

		}

		ret = append(ret, newSR)

	}

	//fmt.Printf("DEBUG SQLTOLDAP ret => %v\n", ret)
	//fmt.Printf("DEBUG SQLTOLDAP ret[0].Attributes => %v\n", ret[0].Attributes)

	return ret, nil
}

func obtenerPassAdmin() (string, error) {

	dat, err := os.ReadFile("/root/.pgpass")
	if err != nil {
		return "", err
	}

	start := "localhost:5432:*:postgres:"
	end := "\n"

	s := strings.Index(string(dat), start)
	if s == -1 {
		return "", errors.New("OBTENER ADMIN PASS => No se pudo leer el archivo")
	}

	s += len(start)

	e := strings.Index(string(dat), end)
	if e == -1 {
		return "", errors.New("OBTENER ADMIN PASS => No se pudo leer el archivo")
	}

	e += s

	return string(dat[s:e]), nil

}

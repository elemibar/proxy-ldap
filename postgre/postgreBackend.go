package postgre

import (
	"context"
	"fmt"
	"net"
	. "proxyldap/ldap"
)

type postgreBackend struct{}

var PostgreBackend Backend = postgreBackend{}

func (postgreBackend) Add(ctx context.Context, state State, req *AddRequest) (*AddResponse, error) {
	fmt.Printf("ADD %+v\n", req)
	return &AddResponse{}, nil
}

func (postgreBackend) Bind(ctx context.Context, state State, req *BindRequest) (*BindResponse, error) {
	fmt.Printf("BIND %+v\n", req)
	return &BindResponse{
		BaseResponse: BaseResponse{
			Code:      ResultSuccess,
			MatchedDN: "",
			Message:   "",
		},
	}, nil
}

func (postgreBackend) Connect(remoteAddr net.Addr) (State, error) {
	return nil, nil
}

func (postgreBackend) Disconnect(state State) {
}

func (postgreBackend) Delete(ctx context.Context, state State, req *DeleteRequest) (*DeleteResponse, error) {
	fmt.Printf("DELETE %+v\n", req)
	return &DeleteResponse{}, nil
}

func (postgreBackend) ExtendedRequest(ctx context.Context, state State, req *ExtendedRequest) (*ExtendedResponse, error) {
	fmt.Printf("EXTENDED %+v\n", req)
	return nil, ProtocolError("unsupported extended request")
}

func (postgreBackend) Modify(ctx context.Context, state State, req *ModifyRequest) (*ModifyResponse, error) {
	fmt.Printf("MODIFY dn=%s\n", req.DN)
	for _, m := range req.Mods {
		fmt.Printf("\t%s %s\n", m.Type, m.Name)
		for _, v := range m.Values {
			fmt.Printf("\t\t%s\n", string(v))
		}
	}
	return &ModifyResponse{}, nil
}

func (postgreBackend) ModifyDN(ctx context.Context, state State, req *ModifyDNRequest) (*ModifyDNResponse, error) {
	fmt.Printf("MODIFYDN %+v\n", req)
	return &ModifyDNResponse{}, nil
}

func (postgreBackend) PasswordModify(ctx context.Context, state State, req *PasswordModifyRequest) ([]byte, error) {
	fmt.Printf("PASSWORD MODIFY %+v\n", req)
	return []byte("genpass"), nil
}

func (postgreBackend) Search(ctx context.Context, state State, req *SearchRequest) (*SearchResponse, error) {
	fmt.Printf("SEARCH %+v\n", req)
	return &SearchResponse{
		BaseResponse: BaseResponse{
			Code:      ResultSuccess, //LDAPResultNoSuchObject,
			MatchedDN: "",
			Message:   "",
		},
		Results: []*SearchResult{
			&SearchResult{
				DN: "cn=admin,dc=example,dc=com",
				Attributes: map[string][][]byte{
					"objectClass": [][]byte{[]byte("person")},
					"cn":          [][]byte{[]byte("admin")},
					"uid":         [][]byte{[]byte("123")},
				},
			},
		},
	}, nil
}

func (postgreBackend) Whoami(ctx context.Context, state State) (string, error) {
	fmt.Println("WHOAMI")
	return "cn=someone,o=somewhere", nil
}

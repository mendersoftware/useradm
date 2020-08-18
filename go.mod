module github.com/mendersoftware/useradm

go 1.14

require (
	github.com/ant0ine/go-json-rest v3.3.3-0.20170913041208-ebb33769ae01+incompatible
	github.com/asaskevich/govalidator v0.0.0-20170903095215-73945b6115bf
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/mendersoftware/go-lib-micro v0.0.0-20200731125022-f9ec108d29b7
	github.com/mendersoftware/mendertesting v0.0.1
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.6.0
	github.com/stretchr/testify v1.6.1
	github.com/urfave/cli v1.22.4
	go.mongodb.org/mongo-driver v1.4.0
	golang.org/x/crypto v0.0.0-20200510223506-06a226fb4e37
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
)

replace github.com/ant0ine/go-json-rest v3.3.3-0.20170913041208-ebb33769ae01+incompatible => github.com/ant0ine/go-json-rest v3.3.2-0.20161106000515-709bbe395d7f+incompatible

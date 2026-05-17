package wireguard

import (
	"bytes"
	"io/ioutil"
	"text/template"

	"github.com/cockroachdb/errors"
)

var profileTemplate = `[Interface]
PrivateKey = {{ .PrivateKey }}
Address = {{ .Address1 }}/32, {{ .Address2 }}/128
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280
[Peer]
PublicKey = {{ .PublicKey }}
Reserved = {{ .Reserved }}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {{ .Endpoint }}
`

type Profile struct {
	profileString string
}

type ProfileData struct {
	PrivateKey string
	Address1   string
	Address2   string
	PublicKey  string
	Endpoint   string
	ClientId   string
}

type profileTemplateData struct {
	*ProfileData
	Reserved string
}

func NewProfile(data *ProfileData) (*Profile, error) {
	profileString, err := generateProfile(data)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Profile{profileString: profileString}, nil
}

func generateProfile(data *ProfileData) (string, error) {
	if data == nil {
		return "", errors.New("profile data is nil")
	}
	reserved, err := FormatClientId(data.ClientId)
	if err != nil {
		return "", errors.Wrap(err, "could not format client_id")
	}
	t, err := template.New("").Parse(profileTemplate)
	if err != nil {
		return "", errors.WithStack(err)
	}
	var result bytes.Buffer
	if err := t.Execute(&result, profileTemplateData{
		ProfileData: data,
		Reserved:    reserved,
	}); err != nil {
		return "", errors.WithStack(err)
	}
	return result.String(), nil
}

func (p *Profile) Save(profileFile string) error {
	return ioutil.WriteFile(profileFile, []byte(p.profileString), 0600)
}

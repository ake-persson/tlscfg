package tlscfg

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

// TODO
// Add default system CA Certs on Linux and Mac OS X

// Options structure.
type Options struct {
	// TLS certificate file (Optional).
	Cert string

	// TLS key file (Optional).
	Key string

	// TLS ca file (Optional).
	CA string

	// TLS insecure (Optional).
	Insecure bool
}

// FetchURI interface.
type TLSCfg interface {
	Config() (*tls.Config, error)
}

type tlsCfg struct {
	cert     string
	key      string
	ca       string
	insecure bool
}

// New constructor.
func New(o *Options) TLSCfg {
	return &tlsCfg{
		cert:     o.Cert,
		key:      o.Key,
		ca:       o.CA,
		insecure: o.Insecure,
	}
}

// Config returns a tls config.
func (t *tlsCfg) Config() (*tls.Config, error) {
	c := tls.Config{
		InsecureSkipVerify: t.insecure,
	}

	if t.cert != "" && t.key != "" {
		cert, err := tls.LoadX509KeyPair(t.cert, t.key)
		if err != nil {
			return nil, err
		}

		c.Certificates = []tls.Certificate{cert}
	}

	if t.ca != "" {
		ca, err := ioutil.ReadFile(t.ca)
		if err != nil {
			return nil, err
		}

		c.RootCAs = x509.NewCertPool()
		c.RootCAs.AppendCertsFromPEM(ca)
	}

	return &c, nil
}

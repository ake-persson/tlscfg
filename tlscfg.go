package tlscfg

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

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

// TLSCfg interface.
type TLSCfg interface {
	Init() error
	Config() *tls.Config
}

type tlsCfg struct {
	cert     string
	key      string
	ca       string
	insecure bool
	config   *tls.Config
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

// Init TLS config.
func (t *tlsCfg) Init() error {
	c := tls.Config{
		InsecureSkipVerify: t.insecure,
	}

	if t.cert != "" && t.key != "" {
		cert, err := tls.LoadX509KeyPair(t.cert, t.key)
		if err != nil {
			return err
		}

		c.Certificates = []tls.Certificate{cert}
	}

	c.RootCAs = x509.NewCertPool()
	if err := appendSystemCerts(&c); err != nil {
		return err
	}

	if t.ca != "" {
		ca, err := ioutil.ReadFile(t.ca)
		if err != nil {
			return err
		}

		c.RootCAs.AppendCertsFromPEM(ca)
	}

	t.config = &c

	return nil
}

// Config returns TLS config
func (t *tlsCfg) Config() *tls.Config {
	return t.config
}

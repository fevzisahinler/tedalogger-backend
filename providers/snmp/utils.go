package snmp

import (
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
)

func prepareSNMPConnection(cfg SNMPConfig) (*gosnmp.GoSNMP, error) {
	var snmpVersion gosnmp.SnmpVersion
	switch cfg.Version {
	case "v2c":
		snmpVersion = gosnmp.Version2c
	case "v3":
		snmpVersion = gosnmp.Version3
	default:
		snmpVersion = gosnmp.Version2c // varsayılan olarak v2c al
	}

	g := &gosnmp.GoSNMP{
		Target:    cfg.Target,
		Port:      cfg.Port,
		Version:   snmpVersion,
		Timeout:   time.Duration(cfg.TimeoutSeconds) * time.Second,
		Retries:   cfg.Retries,
		MaxOids:   gosnmp.MaxOids,
	}

	// v2c ise community ayarlanır
	if cfg.Version == "v2c" {
		g.Community = cfg.Community
	}

	// v3 için güvenlik parametrelerini ayarla
	if cfg.Version == "v3" {
		var authProto gosnmp.SnmpV3AuthProtocol
		var privProto gosnmp.SnmpV3PrivProtocol

		switch cfg.AuthProtocol {
		case "MD5":
			authProto = gosnmp.MD5
		case "SHA":
			authProto = gosnmp.SHA
		default:
			authProto = gosnmp.NoAuth
		}

		switch cfg.PrivProtocol {
		case "DES":
			privProto = gosnmp.DES
		case "AES":
			privProto = gosnmp.AES
		default:
			privProto = gosnmp.NoPriv
		}

		var secLevel gosnmp.SnmpV3SecurityLevel
		switch cfg.SecurityLevel {
		case "noAuthNoPriv":
			secLevel = gosnmp.NoAuthNoPriv
		case "authNoPriv":
			secLevel = gosnmp.AuthNoPriv
		case "authPriv":
			secLevel = gosnmp.AuthPriv
		default:
			secLevel = gosnmp.NoAuthNoPriv
		}

		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 cfg.UserName,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: cfg.AuthPassword,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        cfg.PrivPassword,
		}
		g.MsgFlags = secLevel
	}

	if err := g.Connect(); err != nil {
		return nil, fmt.Errorf("SNMP bağlantısı başarısız: %v", err)
	}

	return g, nil
}

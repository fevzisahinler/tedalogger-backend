package snmp

import (
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
)


func GetCPUMemUsage(cfg SNMPConfig) (float64, float64, error) {
	cpuOID := ".1.3.6.1.2.1.25.3.3.1.2.1"
	totalMemOID := ".1.3.6.1.4.1.2021.4.5.0"
	usedMemOID := ".1.3.6.1.4.1.2021.4.6.0"

	g, err := prepareSNMPConnection(cfg)
	if err != nil {
		return 0, 0, fmt.Errorf("SNMP bağlantı hazırlığı başarısız: %v", err)
	}
	defer g.Conn.Close()

	oids := []string{cpuOID, totalMemOID, usedMemOID}
	result, err := g.Get(oids)
	if err != nil {
		return 0, 0, fmt.Errorf("SNMP Get başarısız: %v", err)
	}

	var cpuUsage float64
	var totalMem float64
	var usedMem float64

	for _, variable := range result.Variables {
		switch variable.Name {
		case cpuOID:
			if val, ok := variable.Value.(int); ok {
				cpuUsage = float64(val)
			}
		case totalMemOID:
			switch val := variable.Value.(type) {
			case uint:
				totalMem = float64(val)
			case int:
				totalMem = float64(val)
			}
		case usedMemOID:
			switch val := variable.Value.(type) {
			case uint:
				usedMem = float64(val)
			case int:
				usedMem = float64(val)
			}
		}
	}

	var memUsage float64
	if totalMem > 0 {
		memUsage = (usedMem / totalMem) * 100
	}

	return cpuUsage, memUsage, nil
}

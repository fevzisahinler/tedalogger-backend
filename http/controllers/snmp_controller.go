package controllers

import (
    "log"
    "tedalogger-backend/http/requests"
    "tedalogger-backend/providers/snmp"

    "github.com/gofiber/fiber/v2"
)

func GetSnmpStats(c *fiber.Ctx) error {
    // JSON body'den parametreleri al
    var req requests.SnmpStatsRequest
    if err := c.BodyParser(&req); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Geçersiz istek verisi: " + err.Error(),
        })
    }

    if err := req.Validate(); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Validasyon hatası: " + err.Error(),
        })
    }

    cfg := snmp.SNMPConfig{
        Target:         req.Target,
        Port:           req.Port,
        Version:        req.Version,
        Community:      req.Community,
        UserName:       req.UserName,
        AuthPassword:   req.AuthPassword,
        AuthProtocol:   req.AuthProtocol,
        PrivPassword:   req.PrivPassword,
        PrivProtocol:   req.PrivProtocol,
        SecurityLevel:  req.SecurityLevel,
        TimeoutSeconds: req.TimeoutSeconds,
        Retries:        req.Retries,
    }

    cpu, mem, err := snmp.GetCPUMemUsage(cfg)
    if err != nil {
        log.Printf("SNMP verisi alınırken hata: %v", err)
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "SNMP bilgisi alınamadı",
        })
    }

    return c.JSON(fiber.Map{
        "cpu_usage": cpu,
        "mem_usage": mem,
    })
}

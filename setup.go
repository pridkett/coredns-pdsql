package pdsql

import (
	"log"

	"github.com/wenerme/coredns-pdsql/pdnsmodel"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/glebarez/sqlite" // use pure go implementation of sqlite driver
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const Default_TTL = 3600

func init() {
	caddy.RegisterPlugin("pdsql", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	backend := PowerDNSGenericSQLBackend{}
	backend.AllowReverse = false

	c.Next()
	if !c.NextArg() {
		return plugin.Error("pdsql", c.ArgErr())
	}
	dialect := c.Val()

	if !c.NextArg() {
		return plugin.Error("pdsql", c.ArgErr())
	}
	arg := c.Val()

	var dialector gorm.Dialector
	switch dialect {
	case "mysql":
		dialector = mysql.Open(arg)
	case "postgres":
		dialector = postgres.Open(arg)
	case "sqlite3", "sqlite":
		dialector = sqlite.Open(arg)

	// Add other dialects as needed
	default:
		return plugin.Error("pdsql", c.Errf("unsupported dialect '%v'", dialect))
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return err
	}

	backend.DB = db

	// anythiung after the the connection string is the zones, defaults to `.`
	backend.Zones = plugin.OriginsFromArgsOrServerBlock(c.RemainingArgs(), c.ServerBlockKeys)

	for c.NextBlock() {
		x := c.Val()
		switch x {
		case "debug":
			args := c.RemainingArgs()
			for _, v := range args {
				switch v {
				case "db":
					backend.DB = backend.DB.Debug()
				}
			}
			backend.Debug = true
			log.Println(Name, "enable log", args)
		case "auto-migrate":
			// currently only use records table
			if err := backend.AutoMigrate(); err != nil {
				return err
			}
		case "fallthrough":
			backend.Fall.SetZonesFromArgs(c.RemainingArgs())
		case "reverse":
			backend.AllowReverse = true
		default:
			return plugin.Error("pdsql", c.Errf("unexpected '%v' command", x))
		}
	}

	if c.NextArg() {
		return plugin.Error("pdsql", c.ArgErr())
	}

	dnsserver.
		GetConfig(c).
		AddPlugin(func(next plugin.Handler) plugin.Handler {
			backend.Next = next
			return backend
		})

	return nil
}

func (pdb PowerDNSGenericSQLBackend) AutoMigrate() error {
	return pdb.DB.AutoMigrate(&pdnsmodel.Domain{}, &pdnsmodel.Record{})
}

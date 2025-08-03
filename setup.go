package pdsql

import (
	"github.com/glebarez/sqlite"
	"github.com/wenerme/coredns-pdsql/pdnsmodel"
	"log"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func init() {
	caddy.RegisterPlugin("pdsql", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

func setup(c *caddy.Controller) error {
	backend, err := ParseConfig(c)
	if err != nil {
		return err
	}

	dnsserver.
		GetConfig(c).
		AddPlugin(func(next plugin.Handler) plugin.Handler {
			backend.Next = next
			return backend
		})

	return nil
}

// ParseConfig parses the configuration for the pdsql plugin
func ParseConfig(c *caddy.Controller) (*PowerDNSGenericSQLBackend, error) {
	backend := &PowerDNSGenericSQLBackend{}
	c.Next()
	if !c.NextArg() {
		return nil, plugin.Error("pdsql", c.ArgErr())
	}
	dialect := c.Val()

	if !c.NextArg() {
		return nil, plugin.Error("pdsql", c.ArgErr())
	}
	arg := c.Val()

	var dialector gorm.Dialector
	switch dialect {
	case "sqlite":
		fallthrough
	case "sqlite3":
		dialector = sqlite.Open(arg)
	case "pg":
		fallthrough
	case "postgresql":
		fallthrough
	case "postgres":
		dialector = postgres.New(postgres.Config{
			DSN: arg,
		})
	case "mysql":
		dialector = mysql.Open(arg)
	default:
		return nil, plugin.Error("pdsql", c.Errf("unsupported dialect %v", dialect))
	}

	db, err := gorm.Open(dialector)
	if err != nil {
		return nil, err
	}
	backend.DB = db

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
				return nil, err
			}
		case "reverse":
			if len(c.RemainingArgs()) > 0 {
				return nil, plugin.Error("pdsql", c.Errf("reverse option takes no arguments"))
			}
			backend.Reverse = true
			log.Println(Name, "reverse DNS lookups enabled")
		case "driver": // todo
		case "dialect": // todo
		case "dsn": // todo
		default:
			return nil, plugin.Error("pdsql", c.Errf("unexpected '%v' command", x))
		}
	}

	if c.NextArg() {
		return nil, plugin.Error("pdsql", c.ArgErr())
	}

	return backend, nil
}

func (pdb PowerDNSGenericSQLBackend) AutoMigrate() error {
	return pdb.DB.AutoMigrate(&pdnsmodel.Domain{}, &pdnsmodel.Record{})
}

package jobs

import (
	"errors"
	"fmt"
	"sync"

	cfenv "github.com/cloudfoundry-community/go-cfenv"

	"github.com/bgentry/que-go"
	"github.com/jackc/pgx"
)

// Return a database object, using the CloudFoundry environment data
func postgresCredsFromCF() (map[string]interface{}, error) {
	appEnv, err := cfenv.Current()
	if err != nil {
		return nil, err
	}

	dbEnv, err := appEnv.Services.WithTag("postgres")
	if err != nil {
		return nil, err
	}

	if len(dbEnv) != 1 {
		return nil, errors.New("expecting 1 database")
	}

	return dbEnv[0].Credentials, nil
}

type dbInitter struct {
	InitSQL            string
	PreparedStatements map[string]string
	OtherStatements    func(*pgx.Conn) error

	// Clearly this won't stop other instances in a race condition, but should at least stop ourselves from hammering ourselves unnecessarily
	runMutex   sync.Mutex
	runAlready bool
}

func (dbi *dbInitter) ensureInitDone(c *pgx.Conn) error {
	dbi.runMutex.Lock()
	defer dbi.runMutex.Unlock()

	if dbi.runAlready {
		return nil
	}

	_, err := c.Exec(dbi.InitSQL)
	if err != nil {
		return err
	}

	dbi.runAlready = true
	return nil
}

func (dbi *dbInitter) AfterConnect(c *pgx.Conn) error {
	if dbi.InitSQL != "" {
		err := dbi.ensureInitDone(c)
		if err != nil {
			return err
		}
	}

	if dbi.OtherStatements != nil {
		err := dbi.OtherStatements(c)
		if err != nil {
			return err
		}
	}

	if dbi.PreparedStatements != nil {
		for n, sql := range dbi.PreparedStatements {
			_, err := c.Prepare(n, sql)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func GetPGXPool(maxConns int, databaseInit string) (*pgx.ConnPool, error) {
	creds, err := postgresCredsFromCF()
	if err != nil {
		return nil, err
	}

	return pgx.NewConnPool(pgx.ConnPoolConfig{
		MaxConnections: maxConns,
		ConnConfig: pgx.ConnConfig{
			Database: creds["name"].(string),
			User:     creds["username"].(string),
			Password: creds["password"].(string),
			Host:     creds["host"].(string),
			Port:     uint16(creds["port"].(float64)),
		},
		AfterConnect: (&dbInitter{
			InitSQL: fmt.Sprintf(`
				CREATE TABLE IF NOT EXISTS que_jobs (
					priority    smallint    NOT NULL DEFAULT 100,
					run_at      timestamptz NOT NULL DEFAULT now(),
					job_id      bigserial   NOT NULL,
					job_class   text        NOT NULL,
					args        json        NOT NULL DEFAULT '[]'::json,
					error_count integer     NOT NULL DEFAULT 0,
					last_error  text,
					queue       text        NOT NULL DEFAULT '',

					CONSTRAINT que_jobs_pkey PRIMARY KEY (queue, priority, run_at, job_id)
				);

				COMMENT ON TABLE que_jobs IS '3';

				CREATE TABLE IF NOT EXISTS cron_metadata (
					id             text                     PRIMARY KEY,
					last_completed timestamp with time zone NOT NULL DEFAULT TIMESTAMP 'EPOCH',
					next_scheduled timestamp with time zone NOT NULL DEFAULT TIMESTAMP 'EPOCH'
				);

				%s
				`, databaseInit),
			OtherStatements:    que.PrepareStatements,
			PreparedStatements: map[string]string{},
		}).AfterConnect,
	})
}

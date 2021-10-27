package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/atredispartners/uds-zoo/uds/node"
	"github.com/atredispartners/uds-zoo/uds/store"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/buntdb"
)

type App struct {
	DB *buntdb.DB
	E  *gin.Engine
}

func (app *App) createInstance(c *gin.Context) {
	var instance store.InstanceRecord
	if err := c.ShouldBindJSON(&instance); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := app.DB.Update(func(tx *buntdb.Tx) error {
		data, err := json.Marshal(instance)
		if err != nil {
			return err
		}
		_, _, err = tx.Set(fmt.Sprintf("%s:instance", instance.ID), string(data), nil)
		c.JSON(http.StatusCreated, instance)
		return err
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
}

func (app *App) getInstances(c *gin.Context) {
	app.DB.View(func(tx *buntdb.Tx) error {
		var instances []store.InstanceRecord
		tx.Ascend("instances", func(key, val string) bool {
			var instance store.InstanceRecord
			if err := json.Unmarshal([]byte(val), &instance); err != nil {
				return false
			}
			instances = append(instances, instance)
			return true
		})
		c.JSON(http.StatusOK, instances)
		return nil
	})

}

func (app *App) getInstance(c *gin.Context) {
	if err := app.DB.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(fmt.Sprintf("%s:instance", c.Param("id")))
		if err != nil {
			return err
		}
		var instance store.InstanceRecord
		if err := json.Unmarshal([]byte(val), &instance); err != nil {
			return err
		}
		c.JSON(http.StatusOK, instance)
		return nil
	}); err != nil {
		c.JSON(404, nil)
	}
}

func (app *App) routeUDS(c *gin.Context) {
	var udsReq node.UDSHTTPRequestResponse
	if err := c.ShouldBindJSON(&udsReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := app.DB.View(func(tx *buntdb.Tx) error {

		val, err := tx.Get(fmt.Sprintf("%s:instance", c.Param("id")))
		if err != nil {
			return err
		}
		var instance store.InstanceRecord
		if err := json.Unmarshal([]byte(val), &instance); err != nil {
			return err
		}

		addrParts := strings.SplitN(instance.Addr, ":", 2)
		if len(addrParts) != 2 {
			return fmt.Errorf("finding network for instance")
		}
		network := addrParts[0]
		addr := addrParts[1]

		var (
			httpc   *http.Client
			httpURL string
		)
		switch network {
		case "unix":
			httpc = &http.Client{
				Transport: &http.Transport{
					DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
						return net.Dial("unix", addr)
					},
				},
			}
			httpURL = "http://unix"
		case "tcp":
			httpc = http.DefaultClient
			httpURL = addr
		default:
			return fmt.Errorf("unknown network type %s", network)
		}
		data, err := json.Marshal(udsReq)
		if err != nil {
			return err
		}
		res, err := httpc.Post(fmt.Sprintf("%s/uds", httpURL), "application/json", bytes.NewBuffer(data))
		if err != nil {
			return err
		}
		if res.StatusCode != http.StatusOK {
			errorText := new(strings.Builder)
			io.Copy(errorText, res.Body)
			return fmt.Errorf("%s", errorText)
		}
		c.Header("Content-Type", "application/json")
		io.Copy(c.Writer, res.Body)
		return nil
	}); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

}

func (app *App) Start(addr string) {
	app.E.Run(addr)
}

type Opts struct {
	DB *buntdb.DB
}

func New(opts *Opts) *App {
	app := App{DB: opts.DB}
	app.DB.CreateIndex("instances", "*:instance", buntdb.IndexString)
	r := gin.Default()
	//r.Use(cors.Default())
	// serve the client app
	r.Static("/client", "./client")
	r.POST("/instances", app.createInstance)
	r.GET("/instances", app.getInstances)
	r.GET("/instances/:id", app.getInstance)
	r.POST("/uds/:id", app.routeUDS)
	//hacky way to serve from '/'
	r.NoRoute(func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/client/index.html")
	})
	app.E = r
	return &app
}

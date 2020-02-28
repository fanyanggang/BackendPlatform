package fredis

import (
	"context"
	"flag"
	"net"
	"time"
	"log"

	"github.com/garyburd/redigo/redis"
)

var (
	WarmRedisAddr     = flag.String("warm_redis", "", "address for warm redis")
	WarmRORedisAddr   = flag.String("warm_ro_redis", "", "ro address for warm redis")
	RedisMaxActive    = flag.Int("redis_max_active", 256, "address for warm redis")
	RedisReadTimeout  = flag.Duration("redis_read_timeout", 50*time.Millisecond, "Timeout for redis read commands.")
	RedisWriteTimeout = flag.Duration("redis_write_timeout", 300*time.Millisecond, "Timeout for redis write commands.")
)

var redisClient *Redis

type Redis struct {
	*ctxRedis
}

type ctxRedis struct {
	Pool     *redis.Pool
	LastTime int64
	Ctx      context.Context
}

//	InitRedis("127.0.0.1:6379")
func InitRedis(addr string) {

	rPool := initRedisConn(addr)

	redisClient = &Redis{
		&ctxRedis{
			Pool:     rPool,
			LastTime: time.Now().UnixNano(),
			Ctx:      context.Background(),
		},
	}
	log.Print("initRedis succ")
}

func GetRedis() *Redis {
	return redisClient
}

func initRedisConn(addr string) *redis.Pool {
	dialer := &net.Dialer{
		Timeout:   3 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	pool := &redis.Pool{
		MaxActive:   *RedisMaxActive,
		IdleTimeout: 10 * time.Minute,
		MaxIdle:     *RedisMaxActive,
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", addr,
				redis.DialNetDial(dialer.Dial),
				redis.DialReadTimeout(*RedisReadTimeout),
				redis.DialReadTimeout(*RedisWriteTimeout))

			if err != nil {
				return nil, err
			}
			return c, nil
		},
		TestOnBorrow: func(c redis.Conn, t time.Time) error {
			_, err := c.Do("PING")
			return err
		},
	}

	return pool
}

func (r *ctxRedis) Set(key, value interface{}) (ret bool, err error) {
	var reply interface{}
	reply, err = r.do("SET", key, value)
	if err != nil {
		return
	}
	rsp := reply.(string)

	if rsp == "OK" {
		ret = true
	}

	return
}

func (r *ctxRedis) SetExSecond(key, value interface{}, dur int) (ret string, err error) {
	var reply interface{}
	reply, err = r.do("SET", key, value, "EX", dur)
	if err != nil {
		return
	}
	ret = reply.(string)
	return
}

func (r *ctxRedis) do(cmd string, args ...interface{}) (reply interface{}, err error) {
	return r.Pool.Get().Do(cmd, args...)
}

func (r *ctxRedis) Get(key string) (ret []byte, err error) {
	var reply interface{}
	reply, err = r.do("GET", key)
	if err != nil {
		if err == redis.ErrNil {
			err = nil
			var tmp []byte
			ret = tmp
		}
		return
	}
	if reply == nil{
		return
	}
	ret = reply.([]byte)
	return
}

func (r *ctxRedis) Del(args ...interface{}) (interface{}, error) {
	var reply interface{}
	reply, err := r.do("DEL", args...)
	if err != nil {
		return reply, nil
	}
	return reply, err
}

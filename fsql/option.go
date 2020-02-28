package fsql

type SQLGroupConfig struct {
	Name   string   `json:"name"`
	Master string   `json:"master"`
	Slaves []string `json:"slaves"`
	//StatLevel string   `toml:"stat_level"`
	//LogFormat string   `toml:"log_format"`
}

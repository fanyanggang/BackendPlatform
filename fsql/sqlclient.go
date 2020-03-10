package fsql

func InitSQLClient(sqlConfig []SQLGroupConfig) error {
	if len(sqlConfig) == 0 {
		return nil
	}

	for _, d := range sqlConfig {
		if d.Master == "" || len(d.Slaves) == 0 {
			return nil
		}

		g, err := NewGroup(d)
		if err != nil {
			return err
		}

		err = SQLGroupManager.Add(d.Name, g)
		if err != nil {
			return err
		}
	}
	return nil
}

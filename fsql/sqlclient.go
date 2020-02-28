package fsql

func InitSQLClient(sqlConfig SQLGroupConfig) error {

	if sqlConfig.Master == "" || len(sqlConfig.Slaves) == 0 {
		return nil
	}

	g, err := NewGroup(sqlConfig)
	if err != nil {
		return err
	}

	err = SQLGroupManager.Add(sqlConfig.Name, g)
	if err != nil {
		return err
	}

	return nil
}

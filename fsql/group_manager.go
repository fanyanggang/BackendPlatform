
package fsql

import (
	"sync"
)

type GroupManager struct {
	mu     sync.RWMutex
	groups map[string]*Group
}

var (
	// SQLGroupManager是GroupManager结构体的全局变量
	SQLGroupManager = newGroupManager()
)

func newGroupManager() *GroupManager {
	return &GroupManager{
		groups: make(map[string]*Group),
	}
}

func (gm *GroupManager) Add(name string, g *Group) error{
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.groups[name]  = g
	return nil
}

func (gm *GroupManager) Get(name string) *Group{
	gm.mu.Lock()
	defer gm.mu.Unlock()
	return gm.groups[name]
}

func Get(name string) *Group{
	return SQLGroupManager.Get(name)
}


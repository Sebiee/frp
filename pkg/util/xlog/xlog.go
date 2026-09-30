// Copyright 2019 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xlog

import (
	"cmp"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/fatedier/frp/pkg/util/log"
)

type LogPrefix struct {
	// Name is the name of the prefix, it won't be displayed in log but used to identify the prefix.
	Name string
	// Value is the value of the prefix, it will be displayed in log.
	Value string
	// The prefix with higher priority will be displayed first, default is 10.
	Priority int
}

// Logger is safe for concurrent use: a client's logger is shared by its
// control's goroutines while a reconnect adds the new run id to it.
type Logger struct {
	mu       sync.Mutex
	prefixes []LogPrefix

	prefixString atomic.Pointer[string] // what every line starts with
}

func New() *Logger {
	l := &Logger{
		prefixes: make([]LogPrefix, 0),
	}
	l.prefixString.Store(new(string))
	return l
}

func (l *Logger) prefix() string {
	if p := l.prefixString.Load(); p != nil {
		return *p
	}
	return ""
}

func (l *Logger) ResetPrefixes() (old []LogPrefix) {
	l.mu.Lock()
	defer l.mu.Unlock()
	old = l.prefixes
	l.prefixes = make([]LogPrefix, 0)
	l.prefixString.Store(new(string))
	return
}

func (l *Logger) AppendPrefix(prefix string) *Logger {
	return l.AddPrefix(LogPrefix{
		Name:     prefix,
		Value:    prefix,
		Priority: 10,
	})
}

func (l *Logger) AddPrefix(prefix LogPrefix) *Logger {
	l.mu.Lock()
	defer l.mu.Unlock()
	found := false
	if prefix.Priority <= 0 {
		prefix.Priority = 10
	}
	for i, p := range l.prefixes {
		if p.Name == prefix.Name {
			found = true
			l.prefixes[i].Value = prefix.Value
			l.prefixes[i].Priority = prefix.Priority
			break
		}
	}
	if !found {
		l.prefixes = append(l.prefixes, prefix)
	}
	l.renderPrefixString()
	return l
}

// renderPrefixString needs l.mu held.
func (l *Logger) renderPrefixString() {
	slices.SortStableFunc(l.prefixes, func(a, b LogPrefix) int {
		return cmp.Compare(a.Priority, b.Priority)
	})
	s := ""
	for _, v := range l.prefixes {
		s += "[" + v.Value + "] "
	}
	l.prefixString.Store(&s)
}

func (l *Logger) Spawn() *Logger {
	l.mu.Lock()
	prefixes := slices.Clone(l.prefixes)
	l.mu.Unlock()
	nl := New()
	nl.prefixes = prefixes
	nl.renderPrefixString()
	return nl
}

func (l *Logger) Errorf(format string, v ...any) {
	log.Logger.WithPrefix(l.prefix()).Errorf(format, v...)
}

func (l *Logger) Warnf(format string, v ...any) {
	log.Logger.WithPrefix(l.prefix()).Warnf(format, v...)
}

func (l *Logger) Infof(format string, v ...any) {
	log.Logger.WithPrefix(l.prefix()).Infof(format, v...)
}

func (l *Logger) Debugf(format string, v ...any) {
	log.Logger.WithPrefix(l.prefix()).Debugf(format, v...)
}

func (l *Logger) Tracef(format string, v ...any) {
	log.Logger.WithPrefix(l.prefix()).Tracef(format, v...)
}

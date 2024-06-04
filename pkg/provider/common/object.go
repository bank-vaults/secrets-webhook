// Copyright © 2024 Bank-Vaults Maintainers
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

package common

type element interface {
	Set(v interface{})
	Get() interface{}
}

type Iterator <-chan element

type mapElement struct {
	m map[string]interface{}
	k string
}

func (e *mapElement) Set(v interface{}) {
	e.m[e.k] = v
}

func (e *mapElement) Get() interface{} {
	return e.m[e.k]
}

type sliceElement struct {
	s []interface{}
	i int
}

func (e *sliceElement) Set(v interface{}) {
	e.s[e.i] = v
}

func (e *sliceElement) Get() interface{} {
	return e.s[e.i]
}

func MapIterator(m map[string]interface{}) Iterator {
	c := make(chan element, len(m))
	for k := range m {
		c <- &mapElement{k: k, m: m}
	}
	close(c)

	return c
}

func SliceIterator(s []interface{}) Iterator {
	c := make(chan element, len(s))
	for i := range s {
		c <- &sliceElement{i: i, s: s}
	}
	close(c)

	return c
}

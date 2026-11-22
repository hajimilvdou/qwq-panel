// SPDX-License-Identifier: AGPL-3.0-only

package main

// pointRing 是固定容量环；所有并发访问由 sampler 的单个锁保护。
type pointRing struct {
	points      []Point
	next, count int
}

func newRing(capacity int) pointRing { return pointRing{points: make([]Point, capacity)} }
func (r *pointRing) add(point Point) {
	if len(r.points) == 0 {
		return
	}
	r.points[r.next] = point.clone()
	r.next = (r.next + 1) % len(r.points)
	if r.count < len(r.points) {
		r.count++
	}
}
func (r *pointRing) latest(limit int) []Point {
	if limit < 0 {
		limit = 0
	}
	if limit > r.count {
		limit = r.count
	}
	result := make([]Point, limit)
	start := (r.next - limit + len(r.points)) % len(r.points)
	for index := range result {
		result[index] = r.points[(start+index)%len(r.points)].clone()
	}
	return result
}

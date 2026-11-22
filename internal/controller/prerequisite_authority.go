// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"github.com/qwq-panel/qwq/internal/platform/problem"
	"github.com/qwq-panel/qwq/internal/prerequisites/hostauth"
)

// ======================== 生产授权后端只装配一次 ========================

type prerequisiteAuthorityHolder struct{ authority *hostauth.Authority }

// SetPrerequisiteAuthority 在开始接收请求前装配真实授权，不开放请求参数切换。
func (c *Controller) SetPrerequisiteAuthority(authority *hostauth.Authority) error {
	if c == nil || c.closed.Load() || authority == nil {
		return prerequisiteSourceUnavailable()
	}
	if !c.prerequisites.CompareAndSwap(nil, &prerequisiteAuthorityHolder{authority: authority}) {
		return problem.New(problem.StateConflict, "证书与域名的宿主授权后端已经装配。")
	}
	return nil
}

func (c *Controller) prerequisiteAuthority() *hostauth.Authority {
	if c == nil || c.closed.Load() {
		return nil
	}
	holder := c.prerequisites.Load()
	if holder == nil {
		return nil
	}
	return holder.authority
}

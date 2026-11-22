// SPDX-License-Identifier: AGPL-3.0-only

package agentsession

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/qwq-panel/qwq/internal/platform/problem"
)

// TestMessagesBeforePagesChronologically covers the before_seq pagination of
// the transcript (gap 6): the newest-limit window, chronological order and the
// owner predicate.
func TestMessagesBeforePagesChronologically(t *testing.T) {
	h := newTestHost(t, func(o *Options) { o.Cores = []Core{&echoCore{text: "answer"}} })
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	for i := 0; i < 3; i++ {
		h.send(ownerHuman, rec.ID, "question")
		h.waitTurn(rec.ID)
	}
	all, err := h.svc.Messages(ctx, ownerHuman, rec.ID, 0)
	if err != nil || len(all) != 6 {
		t.Fatalf("all messages = %d, %v", len(all), err)
	}

	// before_seq absent (0): the newest limit messages, oldest first.
	newest, err := h.svc.MessagesBefore(ctx, ownerHuman, rec.ID, 0, 2)
	if err != nil {
		t.Fatalf("MessagesBefore: %v", err)
	}
	if len(newest) != 2 || newest[0].Seq != all[4].Seq || newest[1].Seq != all[5].Seq {
		t.Fatalf("newest page = %+v, want seqs %d, %d", newest, all[4].Seq, all[5].Seq)
	}

	// before_seq = the first seq of that page: the messages before it, the
	// newest limit of them, still oldest first.
	older, err := h.svc.MessagesBefore(ctx, ownerHuman, rec.ID, newest[0].Seq, 2)
	if err != nil {
		t.Fatalf("MessagesBefore(before): %v", err)
	}
	if len(older) != 2 || older[0].Seq != all[2].Seq || older[1].Seq != all[3].Seq {
		t.Fatalf("older page = %+v, want seqs %d, %d", older, all[2].Seq, all[3].Seq)
	}

	// Nothing precedes the first message.
	if page, err := h.svc.MessagesBefore(ctx, ownerHuman, rec.ID, all[0].Seq, 10); err != nil || len(page) != 0 {
		t.Fatalf("page before the first message = %+v, %v", page, err)
	}
	// The owner predicate is the one of Get: a foreign principal cannot page.
	if _, err := h.svc.MessagesBefore(ctx, ownerOther, rec.ID, 0, 5); !problem.HasCode(err, problem.NotFound) {
		t.Fatalf("foreign page = %v", err)
	}
}

// TestLastMessagePreviewTruncation covers last_message_preview (gap 6): the
// plain text of the newest message, clipped to at most 120 characters on a
// rune boundary.
func TestLastMessagePreviewTruncation(t *testing.T) {
	long := strings.Repeat("好", 150)
	h := newTestHost(t, func(o *Options) { o.Cores = []Core{&echoCore{text: long}} })
	ctx := context.Background()
	rec := h.create(ownerHuman, defaultCreate())
	h.send(ownerHuman, rec.ID, "问")
	h.waitTurn(rec.ID)

	got, err := h.svc.Get(ctx, ownerHuman, rec.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if want := strings.Repeat("好", 120); got.LastMessagePreview != want {
		t.Fatalf("preview = %q (%d bytes), want 120 好", got.LastMessagePreview, len(got.LastMessagePreview))
	}
	if !utf8.ValidString(got.LastMessagePreview) {
		t.Fatalf("preview is not valid UTF-8: %q", got.LastMessagePreview)
	}
	// The list carries the same preview for the unread badge.
	page, err := h.svc.List(ctx, ownerHuman, ListFilter{})
	if err != nil || len(page.Items) != 1 || page.Items[0].LastMessagePreview != got.LastMessagePreview {
		t.Fatalf("list preview = %+v, %v", page, err)
	}
	// A session with no messages has no preview.
	empty := h.create(ownerHuman, CreateRequest{Title: "Empty"})
	blank, err := h.svc.Get(ctx, ownerHuman, empty.ID)
	if err != nil || blank.LastMessagePreview != "" {
		t.Fatalf("empty preview = %q, %v", blank.LastMessagePreview, err)
	}
}

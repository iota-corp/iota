package transform

import (
	"context"
	"fmt"
	"os"

	"github.com/bilals12/iota/pkg/config"
	"github.com/bilals12/iota/pkg/message"
)

type utilityDrop struct{}

func newUtilityDrop(ctx context.Context, cfg config.Config) (*utilityDrop, error) {
	return &utilityDrop{}, nil
}

func (t *utilityDrop) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	return []*message.Message{}, nil
}

type utilityControl struct{}

func newUtilityControl(ctx context.Context, cfg config.Config) (*utilityControl, error) {
	return &utilityControl{}, nil
}

func (t *utilityControl) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	ctrl := message.New().AsControl()
	return []*message.Message{ctrl}, nil
}

type sendStdout struct{}

func newSendStdout(ctx context.Context, cfg config.Config) (*sendStdout, error) {
	return &sendStdout{}, nil
}

func (t *sendStdout) Transform(ctx context.Context, msg *message.Message) ([]*message.Message, error) {
	if msg.IsControl() {
		return []*message.Message{msg}, nil
	}
	_, _ = fmt.Fprintln(os.Stdout, msg.String())
	return []*message.Message{msg}, nil
}

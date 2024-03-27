// Copyright © 2023 Bank-Vaults Maintainers
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

package vault

import (
	"log/slog"

	vaultsdk "github.com/bank-vaults/vault-sdk/vault"
)

var _ vaultsdk.Logger = &ClientLogger{}

type ClientLogger struct {
	Logger *slog.Logger
}

func (l ClientLogger) Trace(msg string, args ...map[string]interface{}) {
	l.Debug(msg, args...)
}

func (l ClientLogger) Debug(msg string, args ...map[string]interface{}) {
	l.Logger.Debug(msg, l.argsToAttrs(args...)...)
}

func (l ClientLogger) Info(msg string, args ...map[string]interface{}) {
	l.Logger.Info(msg, l.argsToAttrs(args...)...)
}

func (l ClientLogger) Warn(msg string, args ...map[string]interface{}) {
	l.Logger.Warn(msg, l.argsToAttrs(args...)...)
}

func (l ClientLogger) Error(msg string, args ...map[string]interface{}) {
	l.Logger.Error(msg, l.argsToAttrs(args...)...)
}

func (ClientLogger) argsToAttrs(args ...map[string]interface{}) []any {
	var attrs []any

	for _, arg := range args {
		for key, value := range arg {
			attrs = append(attrs, slog.Any(key, value))
		}
	}

	return attrs
}
